/* ------------------------------------------------------------------
   Security headers
   ------------------------------------------------------------------
   The same set netlify.toml declares, applied by the server itself so
   that it holds wherever the application runs.

   Why this exists: netlify.toml is read by Netlify and by nothing else.
   On the Plesk deployment it is inert, so hub.vts.edu was serving no
   CSP, no HSTS, no X-Frame-Options and no X-Robots-Tag at all — a
   private staff hub that search engines were free to index. Declaring
   the policy in one host's configuration file made it a property of the
   host; putting it here makes it a property of the application.

   Applied without overwriting: if a host has already set a header (as
   Netlify does from netlify.toml), its value stands. Two CSP headers on
   one response are enforced as the intersection of both, which is a
   quiet way to break a page, so this never adds a second.
   ------------------------------------------------------------------ */

/* Kept byte-identical to the policy in netlify.toml. No inline script
   is used anywhere on the site, so script-src needs no escape hatch —
   which is what makes an injected <script> inert. The two Microsoft
   hosts are for MSAL: connect-src for the token call, frame-src for the
   hidden iframe it renews tokens in. */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com",
  "frame-src 'self' https://login.microsoftonline.com",
  "form-action 'self'",
  "frame-ancestors 'self'",
  "base-uri 'none'",
  "object-src 'none'",
].join("; ");

/* Pages that arrive with a one-time token in the query string. The page
   strips the token from the address bar on load, but its stylesheets and
   scripts are requested before that happens, and every one of those
   requests carries the full URL in Referer — which Apache and nginx
   write to the access log by default. `no-referrer` on these two pages
   keeps live reset and confirmation tokens out of the logs.

   strict-origin-when-cross-origin, the site-wide value, does not help
   here: it sends the full URL for same-origin requests, which is
   exactly the case in question. */
const TOKEN_PAGES = /^\/(reset|verify)(\.html)?$/;

export function referrerPolicyFor(pathname) {
  return TOKEN_PAGES.test(pathname) ? "no-referrer" : "strict-origin-when-cross-origin";
}

/* `secure` says whether this response travels over HTTPS. HSTS is only
   meaningful there — browsers ignore it over plain HTTP — and sending
   it from a local dev server would be noise. */
export function securityHeaders({ pathname = "/", secure = true } = {}) {
  const headers = {
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
    "referrer-policy": referrerPolicyFor(pathname),
    /* The hub is private. Without this a deployed site is indexable,
       which is how internal links end up in search results. */
    "x-robots-tag": "noindex, nofollow",
  };
  if (secure) {
    headers["strict-transport-security"] = "max-age=31536000; includeSubDomains";
  }
  return headers;
}

/* Adds the set to a Response, leaving any header the host already set
   exactly as it is.

   Returns the response to use — which is not always the one passed in.
   Response.redirect() produces a response whose headers are immutable,
   and set() on it throws; the guards below rebuild such a response
   instead. Callers must use the return value, or redirects lose their
   headers (or, before this was handled, failed outright). */
export function applySecurityHeaders(response, { pathname = "/", secure = true } = {}) {
  const headers = securityHeaders({ pathname, secure });

  try {
    for (const [name, value] of Object.entries(headers)) {
      if (!response.headers.has(name)) response.headers.set(name, value);
    }
    return response;
  } catch {
    const merged = new Headers(response.headers);
    for (const [name, value] of Object.entries(headers)) {
      if (!merged.has(name)) merged.set(name, value);
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: merged,
    });
  }
}
