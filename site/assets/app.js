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

    el("user-name").textContent = previewMode ? "Preview" : emailOf(account);
    el("preview-banner").hidden = !previewMode;
    el("signout").hidden = previewMode;

    gate.hidden = true;
    app.hidden = false;
  }

  /* ---------------- sign-in flow ---------------- */

  async function start() {
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

  /* ---------------- wiring ---------------- */

  el("signin").addEventListener("click", () => {
    pca.loginRedirect({
      scopes: ["User.Read"],
      // Ask Entra to reject non-vts.edu accounts before the password step.
      domainHint: cfg.allowedDomains[0],
      prompt: "select_account",
    });
  });

  el("signout").addEventListener("click", () => {
    pca.logoutRedirect({ account: account });
  });

  el("preview").addEventListener("click", () => {
    if (isConfigured) return; // never a bypass once auth is live
    previewMode = true;
    render();
  });

  start();
})();
