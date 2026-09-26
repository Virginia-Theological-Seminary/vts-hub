/* ------------------------------------------------------------------
   The administration page
   ------------------------------------------------------------------
   TEMPORARY DEVELOPMENT AUTHENTICATION. Retires with Microsoft Entra.

   This file decides nothing. Whether the person may administer the hub
   is settled by /api/admin/*, which re-checks the signed session cookie
   against VTS_ADMIN_EMAILS on every single request. Everything here is
   presentation: hiding a form that the server would refuse anyway is a
   courtesy to the person, not a control on them.
   ------------------------------------------------------------------ */
(function () {
  "use strict";

  var CSRF_COOKIE = "vts_csrf";
  var CSRF_HEADER = "X-VTS-CSRF";

  var el = function (id) { return document.getElementById(id); };

  function readCookie(name) {
    var parts = String(document.cookie || "").split(";");
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i].trim();
      if (part.indexOf(name + "=") === 0) {
        return decodeURIComponent(part.slice(name.length + 1));
      }
    }
    return "";
  }

  async function call(path, body) {
    var headers = { accept: "application/json" };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      /* Double-submit, exactly as the auth pages do it: a cross-site
         page can make the browser send the cookie but cannot read it,
         so it cannot produce this header. */
      headers[CSRF_HEADER] = readCookie(CSRF_COOKIE);
    }
    var response;
    try {
      response = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        credentials: "same-origin",
        headers: headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      return { ok: false, data: { error: { message: "No connection to the server." } } };
    }
    var data = null;
    try { data = await response.json(); } catch (err) { /* not JSON */ }
    return { ok: response.ok, status: response.status, data: data || {} };
  }

  /* The CSRF cookie is seeded by /api/auth/context, so that has to
     complete before anything is posted. */
  function seedCsrf() {
    if (readCookie(CSRF_COOKIE)) return Promise.resolve();
    return call("/api/auth/context");
  }

  /* ---------------- messages ---------------- */

  var ACTIONS = {
    invite: {
      hint: "They cannot create an account without one. The code works once, " +
            "and only for the address you type here.",
      heading: "Invitation code",
      why: "Give this to them, having confirmed who they are. It works once, " +
           "and only for that address. Any earlier code for them has stopped working.",
      note: "It is not stored in a form anyone can read back — not even you. " +
            "If it gets lost, issue another.",
    },
    code: {
      hint: "For somebody locked out of their account. Their previous recovery " +
            "code stops working.",
      heading: "Recovery code",
      why: "Give this to them, having confirmed who they are, and ask them to " +
           "set a new password with it at /reset.",
      note: "You never see or choose their password — they do that themselves.",
    },
    confirm: {
      hint: "For somebody who signed up while a confirmation email was required " +
            "and never received it. Only do this when you know the address is theirs.",
      heading: "Confirmed",
      why: "",
      note: "",
    },
  };

  function showAlert(message) {
    var box = el("form-alert");
    box.textContent = message;
    box.hidden = false;
  }

  function clearAlert() {
    el("form-alert").hidden = true;
    el("error-email").hidden = true;
  }

  /* ---------------- the code, shown once ---------------- */

  function showIssued(action, data) {
    var copy = ACTIONS[action];
    el("issued-heading").textContent =
      action === "confirm"
        ? (data.alreadyConfirmed ? "Already confirmed" : "Confirmed")
        : copy.heading + " for " + data.email;

    if (action === "confirm") {
      el("issued-why").textContent = data.alreadyConfirmed
        ? data.email + " could already sign in. Nothing was changed."
        : data.email + " can now sign in with the password they chose at sign-up.";
      el("issued-code").hidden = true;
      el("issued-copy").hidden = true;
      el("issued-note").hidden = true;
    } else {
      el("issued-why").textContent = copy.why;
      el("issued-code").textContent = data.code;
      el("issued-code").hidden = false;
      el("issued-copy").hidden = false;
      el("issued-note").textContent = copy.note;
      el("issued-note").hidden = false;
    }

    el("admin-form").hidden = true;
    el("issued").hidden = false;
    el("issued-code").focus();
  }

  /* ---------------- accounts ---------------- */

  /* The list is unbounded and the reason for opening this page is
     usually one named person, so it is filtered and capped rather than
     printed in full. Anyone who cannot sign in comes first: that is the
     other reason for opening it. */
  var LIMIT = 50;
  var allAccounts = [];

  function renderAccounts() {
    var needle = el("filter").value.trim().toLowerCase();
    var matching = needle
      ? allAccounts.filter(function (a) { return a.email.toLowerCase().indexOf(needle) !== -1; })
      : allAccounts;

    var blocked = allAccounts.filter(function (a) { return a.blocked; }).length;
    var shown = matching.slice(0, LIMIT);

    el("accounts-summary").textContent =
      allAccounts.length + (allAccounts.length === 1 ? " account" : " accounts") +
      (blocked ? ", " + blocked + " unable to sign in" : "") +
      (needle ? " · " + matching.length + " matching" : "") +
      (matching.length > shown.length ? " · showing the first " + LIMIT : "");

    var body = el("accounts-body");
    body.textContent = "";
    shown.forEach(function (account) {
      var tr = document.createElement("tr");
      /* textContent throughout: an address is data, never markup. */
      [account.email, account.role, account.blocked ? "unconfirmed" : "can sign in"]
        .forEach(function (value) {
          var td = document.createElement("td");
          td.textContent = value;
          tr.appendChild(td);
        });
      body.appendChild(tr);
    });
    el("accounts").hidden = shown.length === 0;
  }

  async function loadAccounts() {
    var result = await call("/api/admin/accounts");
    if (!result.ok) {
      el("accounts-summary").textContent = "Could not load the account list.";
      return;
    }
    allAccounts = result.data.accounts || [];
    /* Blocked first; the server already sorted by address within that. */
    allAccounts.sort(function (a, b) {
      return (b.blocked ? 1 : 0) - (a.blocked ? 1 : 0);
    });
    renderAccounts();
  }

  /* ---------------- start ---------------- */

  async function start() {
    await seedCsrf();

    var context = await call("/api/admin/context");

    if (context.status === 401) {
      /* The session went while the page was open. */
      window.location.replace("/login?next=%2Fadmin");
      return;
    }
    if (!context.ok) {
      el("denied-message").textContent =
        (context.data.error && context.data.error.message) ||
        "This page is for hub administrators.";
      el("denied").hidden = false;
      return;
    }

    el("who").textContent = context.data.email || "";
    el("panel").hidden = false;

    var action = el("action");
    var hint = el("action-hint");
    function syncHint() { hint.textContent = ACTIONS[action.value].hint; }
    action.addEventListener("change", syncHint);
    syncHint();

    el("filter").addEventListener("input", renderAccounts);

    el("issued-done").addEventListener("click", function () {
      el("issued").hidden = true;
      el("admin-form").hidden = false;
      el("email").value = "";
      el("email").focus();
      loadAccounts();
    });

    el("issued-copy").addEventListener("click", function () {
      var code = el("issued-code").textContent;
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(code).then(
        function () { el("issued-copy").textContent = "Copied"; },
        function () { el("issued-copy").textContent = "Press Ctrl+C to copy"; }
      );
    });

    el("admin-form").addEventListener("submit", async function (event) {
      event.preventDefault();
      clearAlert();

      var email = el("email").value.trim();
      if (!email) {
        var error = el("error-email");
        error.textContent = "Please enter their VTS email address.";
        error.hidden = false;
        el("email").focus();
        return;
      }

      var button = el("submit");
      button.disabled = true;
      var chosen = action.value;
      var result = await call("/api/admin/" + chosen, { email: email });
      button.disabled = false;

      if (!result.ok) {
        showAlert((result.data.error && result.data.error.message) ||
          "That did not work. Please try again.");
        return;
      }
      el("issued-copy").textContent = "Copy code";
      showIssued(chosen, result.data);
      loadAccounts();
    });

    loadAccounts();
  }

  start();
})();
