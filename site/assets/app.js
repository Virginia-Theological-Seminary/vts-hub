/* ------------------------------------------------------------------
   VTS Hub — sign-in and rendering
   ------------------------------------------------------------------
   Auth model: Microsoft Entra ID, single tenant, authorisation-code
   flow with PKCE. The app is public (no secret) — this is the correct
   and supported pattern for a browser app.

   Two gates:
     1. The `authority` below points at the VTS tenant only, so a
        personal or other-institution Microsoft account cannot sign in.
     2. isAllowed() re-checks the account's address ends @vts.edu, which
        catches guest accounts invited into the tenant.

   Until the Entra app registration exists, a temporary development
   sign-in stands in for all of that. This file does not implement it
   and does not know how it works: it asks window.VTSAuth (assets/
   auth-client.js) who is signed in, and renders. Whichever provider
   answered, what arrives here is the same identity object, and the
   hub's own code below is unchanged.
   ------------------------------------------------------------------ */

(function () {
  "use strict";

  const cfg = window.VTS_CONFIG;
  const PLACEHOLDER = /^REPLACE_WITH_/;
  const isConfigured =
    cfg && !PLACEHOLDER.test(cfg.tenantId) && !PLACEHOLDER.test(cfg.clientId);

  const el = (id) => document.getElementById(id);
  const gate = el("gate");
  const app = el("app");

  let pca = null;
  let account = null;
  let previewMode = false;

  /* Whoever is signed in, however they signed in. Set from the auth
     layer under the development provider, and from the MSAL account
     under Entra. */
  let identity = null;

  /* ---------------- helpers ---------------- */

  function emailOf(acct) {
    return (acct.username || acct.idTokenClaims?.preferred_username || "").toLowerCase();
  }

  function isAllowed(acct) {
    const email = emailOf(acct);
    return (cfg.allowedDomains || []).some((d) => email.endsWith("@" + d.toLowerCase()));
  }

  function showError(msg) {
    const box = el("gate-error");
    box.textContent = msg;
    box.hidden = false;
  }

  function showGate() {
    gate.hidden = false;
    app.hidden = true;
    el("gate-unconfigured").hidden = isConfigured;
    el("signin").disabled = !isConfigured;
  }

  /* ---------------- rendering ---------------- */

  function tile(item) {
    const icon = window.vtsIcon(item.icon);
    const note = item.note ? '<div class="tile-note">' + item.note + "</div>" : "";

    let tag = "";
    if (item.status === "pending") {
      tag = '<span class="tag pending">Still to come</span>';
    } else if (item.kind === "external") {
      tag = '<span class="tag external">Separate log-in</span>';
    } else if (item.meta) {
      tag = '<span class="tag file">' + item.meta + "</span>";
    }

    const body =
      '<div class="tile-body">' +
      '<div class="tile-title">' + item.title + "</div>" +
      note + tag +
      "</div>";

    // Nothing to link to yet — render an inert tile rather than a dead link.
    if (item.status === "pending" || !item.href) {
      return '<div class="tile is-pending">' + icon + body + "</div>";
    }

    const ext = item.kind === "external" ? ' target="_blank" rel="noopener noreferrer"' : "";
    return '<a class="tile" href="' + item.href + '"' + ext + ">" + icon + body + "</a>";
  }

  function render() {
    const sections = window.VTS_SECTIONS;

    el("subnav").innerHTML = sections
      .map((s) => '<a href="#' + s.id + '">' + window.vtsIcon(s.icon) + s.title + "</a>")
      .join("");

    el("sections").innerHTML = sections
      .map(
        (s) =>
          '<section class="section" id="' + s.id + '">' +
          '<div class="section-head">' +
          window.vtsIcon(s.icon) +
          "<h2>" + s.title + "</h2>" +
          "</div>" +
          '<p class="section-blurb">' + s.blurb + "</p>" +
          '<div class="grid">' + s.items.map(tile).join("") + "</div>" +
          "</section>"
      )
      .join("");

    const excluded = window.VTS_EXCLUDED || [];
    if (excluded.length) {
      el("excluded-note").innerHTML =
        "<strong>Kept on the main website rather than moved here:</strong> " +
        excluded.join("; ") + ".";
    }

    el("user-name").textContent = previewMode
      ? "Preview"
      : identity
      ? identity.displayName || identity.email
      : emailOf(account);
    el("preview-banner").hidden = !previewMode;
    el("signout").hidden = previewMode;

    gate.hidden = true;
    app.hidden = false;
  }

  /* ---------------- sign-in flow ---------------- */

  async function start() {
    /* Ask the auth layer who is signed in. Under the temporary
       development provider this is the whole answer and MSAL is never
       reached; under Entra it reports mode "entra" and the existing
       flow below runs untouched. */
    const auth = window.VTSAuth ? await window.VTSAuth.context() : null;

    if (auth && auth.mode === "development") {
      /* The long-standing "/?preview" affordance. protect-app.js has
         already decided whether to serve this page at all, so reaching
         here with ?preview means the server permitted it. */
      if (new URLSearchParams(window.location.search).has("preview")) {
        previewMode = true;
        render();
        return;
      }

      if (auth.authenticated) {
        identity = auth.user;
        render();
        return;
      }

      /* protect-app.js redirects unauthenticated requests before the
         page is served; this catches the remaining case of a page
         restored from cache after the session ended. */
      goToLogin();
      return;
    }

    if (!isConfigured) {
      // Convenience while the site is being reviewed: /?preview goes
      // straight in. Guarded by isConfigured, so the moment real
      // credentials are added this stops working entirely.
      if (/[?&]preview\b/.test(window.location.search)) {
        previewMode = true;
        render();
        return;
      }
      showGate();
      return;
    }

    pca = new msal.PublicClientApplication({
      auth: {
        clientId: cfg.clientId,
        authority: "https://login.microsoftonline.com/" + cfg.tenantId,
        redirectUri: window.location.origin + window.location.pathname,
      },
      cache: { cacheLocation: "sessionStorage" },
    });

    await pca.initialize();

    let result = null;
    try {
      result = await pca.handleRedirectPromise();
    } catch (err) {
      showGate();
      showError("Sign-in failed: " + (err.errorMessage || err.message));
      return;
    }

    account = result?.account || pca.getAllAccounts()[0] || null;

    if (!account) {
      showGate();
      return;
    }

    if (!isAllowed(account)) {
      const bad = emailOf(account);
      account = null;
      showGate();
      showError(
        "This hub is limited to @vts.edu accounts. You are signed in as " +
        bad + ". Sign out of that account and try again."
      );
      return;
    }

    pca.setActiveAccount(account);
    await openFileSession(account);
    render();
  }

  /* Exchange the Entra token for an HttpOnly cookie so that links to
     documents under /files/ are authorised by the edge function.
     If this fails the hub still renders — only downloads are affected. */
  async function openFileSession(acct) {
    try {
      const token = await pca.acquireTokenSilent({
        scopes: ["User.Read"],
        account: acct,
      });
      const res = await fetch("/api/session", {
        method: "POST",
        headers: { authorization: "Bearer " + token.accessToken },
        credentials: "same-origin",
      });
      if (!res.ok) {
        console.warn("Document session not established:", res.status, await res.text());
      }
    } catch (err) {
      console.warn("Document session not established:", err);
    }
  }

  function goToLogin() {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.replace("/login?next=" + next);
  }

  /* ---------------- wiring ---------------- */

  el("signin").addEventListener("click", () => {
    if (!pca) return;
    pca.loginRedirect({
      scopes: ["User.Read"],
      // Ask Entra to reject non-vts.edu accounts before the password step.
      domainHint: cfg.allowedDomains[0],
      prompt: "select_account",
    });
  });

  el("signout").addEventListener("click", () => {
    /* Entra sessions are ended at Microsoft; development sessions are
       ended by destroying the cookie. Either way the user lands on
       /login and the hub is no longer reachable by pressing Back —
       protect-app.js serves this page no-store. */
    if (pca && account) {
      pca.logoutRedirect({ account: account });
      return;
    }
    if (window.VTSAuth) window.VTSAuth.signOut("/login");
  });

  /* A page restored from the back/forward cache does not re-run start(),
     so the session is re-checked on show. Without this, Back after Sign
     out could redisplay the hub from memory. */
  window.addEventListener("pageshow", async (event) => {
    if (!event.persisted || previewMode || !window.VTSAuth) return;
    if (identity && !(await window.VTSAuth.session())) goToLogin();
  });

  el("preview").addEventListener("click", () => {
    if (isConfigured) return; // never a bypass once auth is live
    previewMode = true;
    render();
  });

  start();
})();
