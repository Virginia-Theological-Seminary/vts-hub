/* ------------------------------------------------------------------
   MicrosoftEntraAuth — the production provider, not yet switched on
   ------------------------------------------------------------------
   Nothing here contacts Microsoft. The file exists so the shape of the
   replacement is fixed now, while the temporary provider is being
   written, rather than discovered later: same interface, same return
   values, same session payload. Turning it on is a configuration
   change (AUTH_MODE=entra), not a rewrite.

   How it will work, and why the two password methods stay refused:

     The browser signs in against Entra with MSAL (already vendored in
     site/vendor/, already wired up in site/assets/app.js), then posts
     the resulting access token to /api/session. That endpoint — which
     is already written and working — verifies the token with Microsoft,
     confirms the @vts.edu domain, and issues exactly the same signed
     cookie this project uses everywhere. So Entra sign-in does not go
     through signIn() at all: there is no password for the site to
     receive, which is the entire point.

     What this provider therefore does is describe() itself, so the auth
     pages render the Microsoft button as live rather than "Coming
     Soon", and refuse the password paths outright, so no residue of the
     temporary system can be used once Entra is in charge.

   Remaining work when IT delivers the app registration:
     1. tenantId / clientId into site/assets/config.js (README step 1)
     2. AUTH_MODE=entra in the Netlify environment
     3. map the Entra groups claim onto roles.js in session.js, if the
        dashboards ever need to vary by role
   ------------------------------------------------------------------ */

import { validateEmail } from "../validation.js";

const NOT_ENABLED = {
  ok: false,
  field: "email",
  code: "ENTRA_NOT_ENABLED",
  message:
    "Microsoft sign-in is not available yet. Please use your VTS Hub development account.",
};

export const microsoftEntraAuth = {
  id: "entra",
  label: "Microsoft Entra ID",
  temporary: false,

  /* Passwords are Microsoft's business, never this site's — and so is
     forgetting one. Under Entra the "forgot password" link goes away and
     the user uses Microsoft's own self-service reset. */
  supportsPasswordSignUp: false,
  supportsPasswordSignIn: false,
  supportsPasswordReset: false,

  async signUp() {
    /* Accounts come from the VTS tenant; the site does not create them.
       Provisioning is just-in-time on first successful sign-in. */
    return { ...NOT_ENABLED, code: "SIGNUP_NOT_SUPPORTED" };
  },

  async signIn() {
    return NOT_ENABLED;
  },

  async requestPasswordReset() {
    return { ...NOT_ENABLED, code: "RESET_NOT_SUPPORTED" };
  },

  async resetPassword() {
    return { ...NOT_ENABLED, code: "RESET_NOT_SUPPORTED" };
  },

  /* Microsoft 365 addresses are verified by existing. */
  async resendVerification() {
    return { ...NOT_ENABLED, code: "VERIFY_NOT_SUPPORTED" };
  },

  async verifyEmail() {
    return { ...NOT_ENABLED, code: "VERIFY_NOT_SUPPORTED" };
  },

  /* The domain rule survives the switch unchanged — it is the second
     gate that catches guest accounts invited into the tenant, exactly
     as app.js and protect-files.js already describe. */
  checkDomain(email) {
    return validateEmail(email, "login");
  },

  describe() {
    return {
      mode: "entra",
      temporary: false,
      passwordSignIn: false,
      passwordSignUp: false,
      passwordReset: { available: false, delivery: null },
      emailVerification: { required: false, delivery: null },
      notice: "Sign in with your VTS Microsoft 365 account.",
    };
  },
};
