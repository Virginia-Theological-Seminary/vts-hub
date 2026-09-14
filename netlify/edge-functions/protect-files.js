/* ------------------------------------------------------------------
   Guards /files/*
   ------------------------------------------------------------------
   Every document request must present a valid, unexpired session cookie
   issued by session.js. Without this, the documents would be readable by
   anyone who guessed a URL, and the sign-in screen would be decoration.
   ------------------------------------------------------------------ */

const ALLOWED_DOMAINS = ["vts.edu"];

function unb64url(s) {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(pad + "=".repeat((4 - (pad.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function verify(token, secret) {
  const dot = token.lastIndexOf(".");
  if (dot < 1) return null;

  const body = token.slice(0, dot);
  const mac = unb64url(token.slice(dot + 1));

  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "HMAC", key, mac, new TextEncoder().encode(body)
  );
  if (!valid) return null;

  try {
    return JSON.parse(new TextDecoder().decode(unb64url(body)));
  } catch {
    return null;
  }
}

function denied(reason) {
  return new Response(
    `<!doctype html><meta charset="utf-8">
     <title>Sign-in required</title>
     <body style="font:16px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
                  max-width:34rem;margin:18vh auto;padding:0 1.5rem;color:#1b1d21">
       <h1 style="font-size:20px;color:#293891">Sign-in required</h1>
       <p style="color:#6b7280">${reason}</p>
       <p><a href="/" style="color:#293891">Go to the VTS Hub</a></p>
     </body>`,
    { status: 401, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

export default async (request, context) => {
  const secret = Netlify.env.get("VTS_SESSION_SECRET");
  if (!secret) return denied("This site is not fully configured yet.");

  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)vts_session=([^;]+)/);
  if (!match) return denied("Please sign in with your VTS account first.");

  const payload = await verify(decodeURIComponent(match[1]), secret);
  if (!payload) return denied("Your session could not be verified. Please sign in again.");
  if (!payload.exp || Date.now() > payload.exp) {
    return denied("Your session has expired. Please sign in again.");
  }

  const email = String(payload.email || "").toLowerCase();
  if (!ALLOWED_DOMAINS.some((d) => email.endsWith("@" + d))) {
    return denied("This document is limited to @vts.edu accounts.");
  }

  const response = await context.next();
  response.headers.set("cache-control", "private, no-store");
  return response;
};

export const config = { path: "/files/*" };
