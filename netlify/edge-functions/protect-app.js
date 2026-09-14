/* ------------------------------------------------------------------
   Guards the hub page itself
   ------------------------------------------------------------------
   protect-files.js already stops anyone reading a document without a
   session. This does the same for the hub page, so "you must be signed
   in" is enforced by the server rather than by app.js deciding what to
   render — a check in the browser is a suggestion, not a control.

   It also sets no-store on the page, which is what stops the browser
   showing the signed-in hub again from cache or bfcache after the user
   has pressed Sign out and then Back.
   ------------------------------------------------------------------ */

import { readSession, authMode } from "./lib/auth-service.js";
import { env } from "./lib/runtime.js";

/* The existing "/?preview" affordance, kept working and now stated as
   a rule rather than an accident of the front end.

   It renders the tile directory — titles and links, no documents — for
   people reviewing the build before sign-in exists. It is available
   only while the temporary development auth is in use; the moment
   AUTH_MODE=entra it stops working, which matches what app.js already
   did when real Entra IDs were filled in. Set VTS_ALLOW_PREVIEW=false
   to turn it off sooner. Every document under /files/ stays protected
   in preview mode — protect-files.js does not consult this. */
function previewAllowed(url) {
  if (!url.searchParams.has("preview")) return false;
  if (authMode() !== "development") return false;
  return String(env("VTS_ALLOW_PREVIEW", "true")).toLowerCase() !== "false";
}

export default async (request, context) => {
  const url = new URL(request.url);

  if (!previewAllowed(url)) {
    const session = await readSession(request);
    if (!session) {
      /* next= carries them back to where they were headed. It is read
         back through safeNextPath() in auth-api.js, so it can only ever
         name a path on this site. */
      const next = encodeURIComponent(url.pathname + url.search);
      return Response.redirect(new URL("/login?next=" + next, url.origin), 302);
    }
  }

  const response = await context.next();
  response.headers.set("cache-control", "no-store, must-revalidate");
  return response;
};

export const config = { path: ["/", "/index.html"] };
