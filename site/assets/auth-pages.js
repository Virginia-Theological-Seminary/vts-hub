/* ------------------------------------------------------------------
   VTS Hub — sign-in and sign-up form behaviour
   ------------------------------------------------------------------
   Drives login.html, signup.html, forgot.html, reset.html and
   verify.html; which one is decided by the form present on the page.

   Everything here is convenience: catching a gmail.com address before
   the round trip, ticking off password rules as they are met, saying
   which field is wrong. None of it is a control. The server re-runs
   every rule and is free to disagree — when it does, its message is
   what the user sees.

   All text is written with textContent. No string from a form field,
   a URL or a server response is ever assigned to innerHTML, so there
   is no path from typed input to executed markup.
   ------------------------------------------------------------------ */

(function () {
  "use strict";

  var el = function (id) { return document.getElementById(id); };

  var form =
    el("login-form") || el("signup-form") || el("forgot-form") ||
    el("reset-form") || el("verify-form");
  if (!form) return;

  /* "login" | "signup" | "forgot" | "reset" | "verify" */
  var mode = form.id.replace(/-form$/, "");
  var isSignup = mode === "signup";
  var wantsNewPassword = mode === "signup" || mode === "reset";
  var hasEmail = mode !== "reset" && mode !== "verify";
  var usesLinkToken = mode === "reset" || mode === "verify";

  /* The one-time token from a reset or confirmation link, held in
     memory only. It is read from the URL once and the URL is then
     rewritten without it, so it is not left in the address bar, the
     history, or anything that copies the location. */
  var linkToken = "";
  var submitButton = el("submit");
  var alertBox = el("form-alert");
  var passwordRules = [];
  var allowedDomain = "vts.edu";
  var submitting = false;

  /* ---------------- messages ---------------- */

  /* Kept in step with lib/validation.js. The server owns these strings;
     these copies only spare the user a round trip. */
  var MESSAGES = {
    SIGNUP_DOMAIN:
      "Only VTS email addresses ending in @vts.edu are allowed to create a VTS Hub account.",
    LOGIN_DOMAIN: "Only VTS email addresses are permitted to access VTS Hub.",
    EMAIL_REQUIRED: "Please enter your VTS email address.",
    MISMATCH: "Passwords do not match.",
    PASSWORD_REQUIRED: "Please choose a password.",
    NAME_REQUIRED: "Please enter your first and last name.",
    RESET_DONE: "Your password has been updated. Please sign in with your new password.",
    VERIFY_DONE: "Your email address is confirmed. Please sign in.",
  };

  function showAlert(message, kind) {
    alertBox.textContent = message;
    alertBox.classList.toggle("is-success", kind === "success");
    alertBox.hidden = false;
  }

  function clearAlert() {
    alertBox.hidden = true;
    alertBox.textContent = "";
    alertBox.classList.remove("is-success");
  }

  function setFieldError(name, message) {
    var wrapper = el("field-" + name);
    var target = el("error-" + name);
    if (!wrapper || !target) return;

    if (message) {
      target.textContent = message;
      target.hidden = false;
      wrapper.classList.add("has-error");
    } else {
      target.textContent = "";
      target.hidden = true;
      wrapper.classList.remove("has-error");
    }
  }

  function clearFieldErrors() {
    ["firstName", "lastName", "email", "password", "confirmPassword"].forEach(function (name) {
      setFieldError(name, "");
    });
  }

  function focusField(name) {
    var input = el(name);
    if (input && typeof input.focus === "function") input.focus();
  }

  /* ---------------- the destination after sign-in ---------------- */

  /* Mirrors safeNextPath() in auth-api.js. The server sanitises this
     again on its side; doing it here as well means a tampered link
     cannot even briefly point the form somewhere off-site. */
  function safeNext() {
    var raw = "";
    try {
      raw = new URLSearchParams(window.location.search).get("next") || "";
    } catch (err) {
      return "";
    }
    if (raw.indexOf("/") !== 0) return "";
    if (raw.indexOf("//") === 0 || raw.indexOf("/\\") === 0) return "";
    if (/[\\\u0000-\u001F\u007F]/.test(raw)) return "";
    if (/^\/[a-z0-9+.-]*:/i.test(raw)) return "";
    return raw;
  }

  /* ---------------- password rule checklist ---------------- */

  function renderPasswordRules() {
    var list = el("pw-rules");
    if (!list || !passwordRules.length) return;

    list.textContent = "";
    passwordRules.forEach(function (rule) {
      var item = document.createElement("li");
      item.id = "pw-rule-" + rule.id;
      item.textContent = rule.label;
      list.appendChild(item);
    });
  }

  /* The same five tests the server applies, so the ticks cannot promise
     something the server will then refuse. */
  var RULE_TESTS = {
    length: function (v) { return v.length >= 8; },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    number: function (v) { return /[0-9]/.test(v); },
    special: function (v) { return /[^A-Za-z0-9]/.test(v); },
  };

  function updatePasswordRules() {
    var input = el("password");
    if (!input || !passwordRules.length) return true;

    var value = input.value;
    var met = 0;

    passwordRules.forEach(function (rule) {
      var item = el("pw-rule-" + rule.id);
      var test = RULE_TESTS[rule.id];
      var passes = test ? test(value) : false;
      if (passes) met++;
      if (item) item.classList.toggle("met", passes);
    });

    var status = el("pw-status");
    if (status) {
      status.textContent = value
        ? met + " of " + passwordRules.length + " password requirements met."
        : "";
    }
    return met === passwordRules.length;
  }

  /* ---------------- friendly pre-checks ---------------- */

  function normalizeEmail(value) {
    return String(value || "").trim().toLowerCase();
  }

  function localEmailProblem(value) {
    var email = normalizeEmail(value);
    if (!email) return MESSAGES.EMAIL_REQUIRED;

    var at = email.lastIndexOf("@");
    if (at < 1 || email.indexOf(" ") !== -1) {
      return isSignup ? MESSAGES.SIGNUP_DOMAIN : MESSAGES.LOGIN_DOMAIN;
    }
    if (email.slice(at + 1) !== allowedDomain) {
      return isSignup ? MESSAGES.SIGNUP_DOMAIN : MESSAGES.LOGIN_DOMAIN;
    }
    return "";
  }

  function validateBeforeSend() {
    clearFieldErrors();
    var firstBad = null;

    /* The confirmation page is a single button. */
    if (mode === "verify") return null;

    if (isSignup) {
      if (!el("firstName").value.trim() || !el("lastName").value.trim()) {
        setFieldError("firstName", MESSAGES.NAME_REQUIRED);
        firstBad = firstBad || "firstName";
      }
    }

    if (hasEmail) {
      var emailProblem = localEmailProblem(el("email").value);
      if (emailProblem) {
        setFieldError("email", emailProblem);
        firstBad = firstBad || "email";
      }
    }

    /* The forgot form asks for nothing but an address. */
    if (mode === "forgot") return firstBad;

    if (!el("password").value) {
      setFieldError("password", MESSAGES.PASSWORD_REQUIRED);
      firstBad = firstBad || "password";
    } else if (wantsNewPassword && !updatePasswordRules()) {
      setFieldError("password", "Your password does not meet all of the requirements below.");
      firstBad = firstBad || "password";
    }

    if (wantsNewPassword && el("password").value !== el("confirmPassword").value) {
      setFieldError("confirmPassword", MESSAGES.MISMATCH);
      firstBad = firstBad || "confirmPassword";
    }

    return firstBad;
  }

  /* ---------------- submission ---------------- */

  var LABELS = {
    login: ["Sign in", "Signing in…"],
    signup: ["Create account", "Creating account…"],
    forgot: ["Send reset link", "Sending…"],
    reset: ["Update password", "Updating…"],
    verify: ["Confirm my email address", "Confirming…"],
  };

  function setBusy(busy) {
    submitting = busy;
    submitButton.disabled = busy;
    submitButton.classList.toggle("is-busy", busy);
    submitButton.textContent = LABELS[mode][busy ? 1 : 0];
  }

  /* Where each form sends its fields. */
  async function send() {
    if (mode === "forgot") {
      return window.VTSAuth.forgotPassword({ email: el("email").value });
    }
    if (mode === "reset") {
      return window.VTSAuth.resetPassword({
        token: linkToken,
        password: el("password").value,
        confirmPassword: el("confirmPassword").value,
      });
    }
    if (mode === "verify") {
      return window.VTSAuth.verifyEmail({ token: linkToken });
    }
    var fields = { email: el("email").value, password: el("password").value };
    if (isSignup) {
      fields.firstName = el("firstName").value;
      fields.lastName = el("lastName").value;
      fields.confirmPassword = el("confirmPassword").value;
      return window.VTSAuth.signUp(fields);
    }
    fields.next = safeNext();
    return window.VTSAuth.signIn(fields);
  }

  /* The "we sent you a link" state, shared by forgot and sign-up. Where
     to look for the link depends on how mail leaves the site; the server
     says which, so this page never guesses. */
  function showSent(data) {
    form.hidden = true;
    var sent = el("sent");
    var message = el("sent-message");
    var hint = el("sent-hint");
    if (message) message.textContent = data.message || "";

    if (hint) {
      hint.textContent = "";
      if (data.delivery === "outbox") {
        hint.appendChild(document.createTextNode("Local development: the message is in the "));
        var link = document.createElement("a");
        link.href = "/__dev/outbox";
        link.textContent = "dev outbox";
        hint.appendChild(link);
        hint.appendChild(document.createTextNode("."));
        hint.hidden = false;
      } else if (data.delivery === "log") {
        hint.textContent =
          "While Microsoft Entra sign-in is being configured, reset links are " +
          "delivered through the VTS development team. Contact them if it does not arrive.";
        hint.hidden = false;
      }
    }
    if (sent) sent.hidden = false;
  }

  function showDeadLink() {
    form.hidden = true;
    alertBox.hidden = true;
    var noToken = el("no-token");
    if (noToken) noToken.hidden = false;
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (submitting) return;

    clearAlert();
    var firstBad = validateBeforeSend();
    if (firstBad) {
      focusField(firstBad);
      return;
    }

    setBusy(true);
    var result = await send();

    if (result.ok) {
      if (mode === "forgot" || (mode === "signup" && result.data.verification === "sent")) {
        setBusy(false);
        showSent(result.data);
        return;
      }
      /* replace(), not assign(): none of these pages should be sitting
         in history behind the page that follows them. */
      window.location.replace(result.data.next || safeNext() || "/");
      return;
    }

    setBusy(false);

    /* A dead link cannot be fixed by trying again on this page. */
    if (result.code === "RESET_INVALID" || result.code === "VERIFY_INVALID") {
      showDeadLink();
      return;
    }

    /* Right password, unconfirmed address: offer to send the link again
       for the address they just typed. */
    if (result.code === "EMAIL_UNVERIFIED") {
      showAlert(result.message);
      var resend = el("resend");
      if (resend) resend.hidden = false;
      return;
    }

    if (result.field) setFieldError(result.field, result.message);
    showAlert(result.message);

    if (result.code === "ACCOUNT_EXISTS") {
      focusField("email");
    } else if (result.field && el(result.field)) {
      focusField(result.field);
    }

    /* A wrong password should not be left sitting in the box. */
    if (result.code === "INVALID_CREDENTIALS") {
      var password = el("password");
      if (password) password.value = "";
    }
  });

  /* "Send the confirmation link again" — only ever shown after a
     correct password on an unconfirmed account. */
  var resendButton = el("resend-btn");
  if (resendButton) {
    resendButton.addEventListener("click", async function () {
      resendButton.disabled = true;
      var result = await window.VTSAuth.resendVerification({ email: el("email").value });
      var hint = el("resend-hint");
      if (hint) {
        hint.textContent = result.ok
          ? result.data.message +
            (result.data.delivery === "outbox" ? " (Local development: see the dev outbox.)" : "")
          : result.message;
        hint.hidden = false;
      }
      if (!result.ok) resendButton.disabled = false;
    });
  }

  /* Clear a field's error as soon as the user starts fixing it. */
  ["firstName", "lastName", "email", "password", "confirmPassword"].forEach(function (name) {
    var input = el(name);
    if (!input) return;
    input.addEventListener("input", function () {
      setFieldError(name, "");
      if (name === "password") updatePasswordRules();
      if (name === "confirmPassword" || name === "password") {
        var confirm = el("confirmPassword");
        if (confirm && confirm.value && confirm.value !== el("password").value) {
          setFieldError("confirmPassword", MESSAGES.MISMATCH);
        }
      }
    });
  });

  /* ---------------- page setup ---------------- */

  /* The server decides what these pages offer. If it reports that Entra
     is the live provider, the password form goes away and the Microsoft
     button becomes the real one — without this file being edited. */
  function applyContext(context) {
    if (!context) {
      showAlert(
        "We couldn't reach the sign-in service. Please reload the page and try again."
      );
      return;
    }

    allowedDomain = context.allowedDomain || allowedDomain;
    passwordRules = context.passwordRules || [];
    renderPasswordRules();
    updatePasswordRules();

    var microsoft = context.microsoft || {};
    var button = el("microsoft-btn");
    var chip = el("microsoft-chip");
    var help = el("microsoft-help");

    if (button) {
      /* Stays disabled unless the server says Entra is live. There is
         no click handler on this element in either state — turning it
         on is a separate piece of work, and until then the button
         cannot begin an authentication attempt. */
      button.disabled = !microsoft.available;
      button.setAttribute("aria-disabled", String(!microsoft.available));
      if (microsoft.label) el("microsoft-label").textContent = microsoft.label;
      if (chip) {
        chip.textContent = microsoft.status || "";
        chip.hidden = !microsoft.status;
      }
    }
    if (help && microsoft.help) help.textContent = microsoft.help;
    if (help && !microsoft.help) help.hidden = true;

    if (!context.configured) {
      showAlert(
        "Sign-in is not configured on this site yet. A VTS administrator needs to set " +
          "VTS_SESSION_SECRET in the Netlify environment (see README step 2)."
      );
      submitButton.disabled = true;
    }

    /* Each of these is a provider capability, not a given. Under Entra
       every password form goes away, and so does the link to one. */
    var reset = context.passwordReset || {};
    var verification = context.emailVerification || {};
    var allowed = {
      login: context.passwordSignIn,
      signup: context.passwordSignUp,
      forgot: reset.available,
      reset: reset.available,
      verify: verification.required,
    }[mode];

    if (context.configured && !allowed) {
      form.hidden = true;
      showAlert(context.notice || "Please sign in with Microsoft.");
    }

    var forgotLink = el("forgot-link");
    if (forgotLink && !reset.available) forgotLink.hidden = true;
  }

  /* The reset and confirmation pages are only useful with a token. It
     is taken from the URL exactly once, then the URL is rewritten
     without it. */
  function takeLinkToken() {
    var token = "";
    try {
      token = new URLSearchParams(window.location.search).get("token") || "";
    } catch (err) {
      token = "";
    }
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, "", window.location.pathname);
    }
    return token;
  }

  (async function start() {
    /* One request, not two: the context already says whether anyone is
       signed in, so asking the session endpoint as well would only add a
       round trip and an expected 401 in the console. */
    if (usesLinkToken) {
      linkToken = takeLinkToken();
      if (!linkToken) showDeadLink();
    }

    /* Back from a successful reset or confirmation: say so, once. */
    if (mode === "login") {
      try {
        var arrived = new URLSearchParams(window.location.search);
        if (arrived.has("reset")) showAlert(MESSAGES.RESET_DONE, "success");
        if (arrived.has("verified")) showAlert(MESSAGES.VERIFY_DONE, "success");
        if (arrived.has("reset") || arrived.has("verified")) {
          window.history.replaceState(null, "", window.location.pathname);
        }
      } catch (err) {
        /* nothing to show */
      }
    }

    var context = await window.VTSAuth.context(true);

    /* Already signed in? Then this page has nothing to ask. (Not on the
       token pages: someone may be resetting from a signed-in browser,
       and the reset clears that session when it succeeds.) */
    if (context && context.authenticated && !usesLinkToken) {
      window.location.replace(safeNext() || "/");
      return;
    }

    /* Carry ?next through to the sign-up page so a deep link survives a
       detour via account creation. */
    var next = safeNext();
    if (next) {
      var cross = el("signup-link") || el("login-link");
      if (cross) cross.href = cross.getAttribute("href") + "?next=" + encodeURIComponent(next);
    }

    applyContext(context);
  })();
})();
