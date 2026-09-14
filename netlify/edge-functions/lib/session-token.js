/* ------------------------------------------------------------------
   Session tokens
   ------------------------------------------------------------------
   Wire format is deliberately IDENTICAL to the one session.js already
   issues for Entra sign-ins:

       base64url(JSON payload) "." base64url(HMAC-SHA-256 of that)

   That is what lets protect-files.js keep guarding /files/* without a
   single change: it verifies the signature, checks `exp`, and checks
   the address ends @vts.edu — all of which hold for the sessions minted
   here too. One cookie, one guard, two possible issuers.

   The payload carries only what is needed to identify the user, per the
   brief: userId, email, first/last name, role. No password material of
   any kind is placed in a session, hashed or otherwise.
   ------------------------------------------------------------------ */

import { b64url, unb64url, encode, decode, timingSafeEqual, env, randomId } from "./runtime.js";

export const SESSION_COOKIE = "vts_session";
export const CSRF_COOKIE = "vts_csrf";
export const CSRF_HEADER = "x-vts-csrf";

/* Matches the 8 hours session.js already uses for Entra sessions. */
export const SESSION_HOURS = 8;

/* The signing secret is the one the site already documents in the
   README (Netlify -> Environment variables). Never hard-coded, never
   defaulted: with no secret the auth endpoints refuse to issue
   sessions rather than signing with something guessable. */
export function sessionSecret() {
  return env("VTS_SESSION_SECRET") || null;
}

async function hmacKey(secret, usages) {
  return crypto.subtle.importKey(
    "raw",
    encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages
  );
}

export async function signSession(payload, secret) {
  const key = await hmacKey(secret, ["sign"]);
  const body = b64url(encode(JSON.stringify(payload)));
  const mac = await crypto.subtle.sign("HMAC", key, encode(body));
  return body + "." + b64url(mac);
}

/* Returns the payload or null. Verifies the signature before parsing,
   so untrusted bytes are never handed to JSON.parse on the strength of
   an attacker's say-so. */
export async function verifySession(token, secret) {
  try {
    const dot = String(token ?? "").lastIndexOf(".");
    if (dot < 1) return null;

    const body = token.slice(0, dot);
    const mac = unb64url(token.slice(dot + 1));
    const key = await hmacKey(secret, ["sign"]);

    /* Recompute rather than crypto.subtle.verify so the comparison
       goes through the same constant-time helper used elsewhere. */
    const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, encode(body)));
    if (!timingSafeEqual(mac, expected)) return null;

    const payload = JSON.parse(decode(unb64url(body)));
    if (!payload || typeof payload !== "object") return null;
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

/* Builds the payload from a user record. A fresh `sid` is generated on
   every call, which is what defeats session fixation: a session id the
   client arrived with is never reused or honoured — sign-in always
   replaces the cookie with a newly minted one. */
export function sessionPayload(user, provider) {
  const now = Date.now();
  return {
    v: 1,
    sid: randomId(18),
    sub: user.id,
    email: user.email,
    firstName: user.firstName || "",
    lastName: user.lastName || "",
    role: user.role,
    provider,
    iat: now,
    exp: now + SESSION_HOURS * 3600 * 1000,
  };
}

/* What the browser is allowed to know about the signed-in user. Built
   from the session payload by picking fields, not by deleting them, so
   a field added to the payload later cannot leak by omission. */
export function publicIdentity(payload) {
  if (!payload) return null;
  return {
    id: payload.sub,
    email: payload.email,
    firstName: payload.firstName || "",
    lastName: payload.lastName || "",
    displayName:
      [payload.firstName, payload.lastName].filter(Boolean).join(" ") || payload.email,
    role: payload.role,
    provider: payload.provider,
    expiresAt: payload.exp,
  };
}
