/* ------------------------------------------------------------------
   VTS Hub — sign-in and sign-up form behaviour
   ------------------------------------------------------------------
   Drives both login.html and signup.html; which one is decided by the
   form that is present on the page.

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

  var loginForm = el("login-form");
  var signupForm = el("signup-form");
  var form = loginForm || signupForm;
  if (!form) return;

  var isSignup = Boolean(signupForm);
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

    if (isSignup) {
      if (!el("firstName").value.trim() || !el("lastName").value.trim()) {
        setFieldError("firstName", MESSAGES.NAME_REQUIRED);
        firstBad = firstBad || "firstName";
      }
    }

    var emailProblem = localEmailProblem(el("email").value);
    if (emailProblem) {
      setFieldError("email", emailProblem);
      firstBad = firstBad || "email";
    }

    if (!el("password").value) {
      setFieldError("password", MESSAGES.PASSWORD_REQUIRED);
      firstBad = firstBad || "password";
    } else if (isSignup && !updatePasswordRules()) {
      setFieldError("password", "Your password does not meet all of the requirements below.");
      firstBad = firstBad || "password";
    }

    if (isSignup && el("password").value !== el("confirmPassword").value) {
      setFieldError("confirmPassword", MESSAGES.MISMATCH);
      firstBad = firstBad || "confirmPassword";
    }

    return firstBad;
  }

  /* ---------------- submission ---------------- */

  function setBusy(busy, label) {
    submitting = busy;
    submitButton.disabled = busy;
    submitButton.classList.toggle("is-busy", busy);
    submitButton.textContent = busy
      ? label
      : isSignup
      ? "Create account"
      : "Sign in";
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

    setBusy(true, isSignup ? "Creating account…" : "Signing in…");

    var fields = {
      email: el("email").value,
      password: el("password").value,
    };
    if (isSignup) {
      fields.firstName = el("firstName").value;
      fields.lastName = el("lastName").value;
      fields.confirmPassword = el("confirmPassword").value;
    } else {
      fields.next = safeNext();
    }

    var result = isSignup
      ? await window.VTSAuth.signUp(fields)
      : await window.VTSAuth.signIn(fields);

    if (result.ok) {
      /* replace(), not assign(): the sign-in page should not be sitting
         in history behind the hub. */
      window.location.replace(result.data.next || safeNext() || "/");
      return;
    }

    setBusy(false);

    if (result.field) setFieldError(result.field, result.message);
    showAlert(result.message);

    if (result.code === "ACCOUNT_EXISTS") {
      focusField("email");
    } else if (result.field) {
      focusField(result.field);
    }

    /* A wrong password should not be left sitting in the box. */
    if (result.code === "INVALID_CREDENTIALS") {
      var password = el("password");
      if (password) password.value = "";
    }
  });

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

    /* Password sign-in is a provider capability, not a given. */
    if (context.configured && ((isSignup && !context.passwordSignUp) ||
        (!isSignup && !context.passwordSignIn))) {
      form.hidden = true;
      showAlert(context.notice || "Please sign in with Microsoft.");
    }
  }

  (async function start() {
    /* One request, not two: the context already says whether anyone is
       signed in, so asking the session endpoint as well would only add a
       round trip and an expected 401 in the console. */
    var context = await window.VTSAuth.context(true);

    /* Already signed in? Then this page has nothing to ask. */
    if (context && context.authenticated) {
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
