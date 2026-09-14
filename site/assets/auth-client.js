/* ------------------------------------------------------------------
   VTS Hub — auth client
   ------------------------------------------------------------------
   The browser's single door to the auth layer. Every page talks to
   window.VTSAuth; no page talks to /api/auth/* directly, and no page
   knows whether a password or Microsoft Entra answered the question.
   That is the front-end half of the seam described in
   netlify/edge-functions/lib/auth-service.js — when the temporary
   development auth is replaced, this file's surface does not change.

   Nothing sensitive is kept here. There is no token in localStorage,
   no token in sessionStorage, and no password anywhere: the session
   lives in an HttpOnly cookie that script cannot read, which is the
   point of it being HttpOnly.
   ------------------------------------------------------------------ */

(function () {
  "use strict";

  var CSRF_COOKIE = "vts_csrf";
  var CSRF_HEADER = "X-VTS-CSRF";

  var contextPromise = null;

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

  /* One shape for every answer, so callers never have to tell a network
     failure apart from a rejection by hand. */
  function settle(response, body) {
    if (response.ok) {
      return { ok: true, status: response.status, data: body || {} };
    }
    var error = (body && body.error) || {};
    return {
      ok: false,
      status: response.status,
      code: error.code || "SERVER_ERROR",
      field: error.field || response.headers.get("x-vts-field") || "",
      message:
        error.message || "We couldn't complete your request right now. Please try again.",
    };
  }

  function offline() {
    return {
      ok: false,
      status: 0,
      code: "NETWORK",
      field: "",
      message: "We couldn't reach the server. Check your connection and try again.",
    };
  }

  async function call(path, options) {
    var opts = options || {};
    var headers = { accept: "application/json" };

    if (opts.body !== undefined) {
      headers["content-type"] = "application/json";
      /* Double-submit: the server compares this against the cookie of
         the same name. A cross-site page can make the browser send the
         cookie but cannot read it, so it cannot produce this header. */
      headers[CSRF_HEADER] = readCookie(CSRF_COOKIE);
    }

    var response;
    try {
      response = await fetch(path, {
        method: opts.method || "GET",
        credentials: "same-origin",
        headers: headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      });
    } catch (err) {
      return offline();
    }

    var body = null;
    try {
      body = await response.json();
    } catch (err) {
      /* A non-JSON body is a proxy or an outage, not an answer. */
    }
    return settle(response, body);
  }

  /* Fetching the context is also what seeds the CSRF cookie, so it must
     complete before any POST. The auth pages await it on load. */
  async function context(force) {
    if (force || !contextPromise) {
      contextPromise = call("/api/auth/context");
    }
    var result = await contextPromise;
    return result.ok ? result.data : null;
  }

  async function ensureCsrf() {
    if (!readCookie(CSRF_COOKIE)) await context(true);
  }

  var VTSAuth = {
    context: context,

    /* The signed-in identity, or null. Asks the server every time —
       the client's opinion about whether it is signed in is worth
       nothing, and the cookie may have expired since the page loaded. */
    async session() {
      var result = await call("/api/auth/session");
      return result.ok ? result.data.user : null;
    },

    async signUp(fields) {
      await ensureCsrf();
      return call("/api/auth/signup", {
        method: "POST",
        body: {
          firstName: fields.firstName,
          lastName: fields.lastName,
          email: fields.email,
          password: fields.password,
          confirmPassword: fields.confirmPassword,
        },
      });
    },

    async signIn(fields) {
      await ensureCsrf();
      return call("/api/auth/login", {
        method: "POST",
        body: {
          email: fields.email,
          password: fields.password,
          next: fields.next || "",
        },
      });
    },

    /* Ends the session server-side, then leaves by replacing the history
       entry rather than pushing one, so Back cannot return to the
       authenticated page. The hub page is also served no-store, so
       there is no cached copy for Back to find. */
    async signOut(destination) {
      await call("/api/auth/logout", { method: "POST", body: {} });
      contextPromise = null;
      window.location.replace(destination || "/login");
    },
  };

  window.VTSAuth = VTSAuth;
})();
