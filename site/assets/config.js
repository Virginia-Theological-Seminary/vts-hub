/* ------------------------------------------------------------------
   VTS Hub — configuration
   ------------------------------------------------------------------
   VTS IT: these are the only two values you need to fill in.
   See README.md for how to obtain them (Entra ID app registration).
   There is NO client secret — a browser app must never hold one.
   ------------------------------------------------------------------ */

window.VTS_CONFIG = {
  // Directory (tenant) ID for the vts.edu Microsoft 365 tenant.
  tenantId: "REPLACE_WITH_VTS_TENANT_ID",

  // Application (client) ID of the SPA registered in Entra ID.
  clientId: "REPLACE_WITH_APP_CLIENT_ID",

  // Only accounts whose sign-in address ends in one of these is admitted.
  // The tenant restriction above is the real gate; this is a second check
  // in case guest accounts are ever invited into the tenant.
  allowedDomains: ["vts.edu"],
};
