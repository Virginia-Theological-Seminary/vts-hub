/* ------------------------------------------------------------------
   Small runtime helpers shared by the auth edge functions.
   ------------------------------------------------------------------
   Deliberately dependency-free and runtime-agnostic: the same modules
   run on Netlify Edge (Deno) in production and under plain Node for
   the local dev server and the test harness. Everything here is either
   a Web API (crypto.subtle, TextEncoder, Response) or hand-rolled.
   ------------------------------------------------------------------ */

const enc = new TextEncoder();
const dec = new TextDecoder();

export const encode = (s) => enc.encode(s);
export const decode = (b) => dec.decode(b);

/* Environment access. Netlify Edge exposes Netlify.env, Deno exposes
   Deno.env, Node exposes process.env. `typeof` guards keep this from
   throwing a ReferenceError on whichever ones are absent. */
export function env(name, fallback = undefined) {
  let v;
  try {
    if (typeof Netlify !== "undefined" && Netlify?.env?.get) v = Netlify.env.get(name);
  } catch { /* not on Netlify */ }
  if (v === undefined || v === null || v === "") {
    try {
      if (typeof Deno !== "undefined" && Deno?.env?.get) v = Deno.env.get(name);
    } catch { /* no env permission */ }
  }
  if ((v === undefined || v === null || v === "") && typeof process !== "undefined") {
    v = process?.env?.[name];
  }
  return v === undefined || v === null || v === "" ? fallback : v;
}

export function b64url(bytes) {
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(s) {
  const pad = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(pad + "=".repeat((4 - (pad.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function randomId(bytes = 16) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256Hex(input) {
  const digest = await crypto.subtle.digest("SHA-256", encode(String(input)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* Length-independent comparison. Compares digests rather than the raw
   values so an attacker cannot learn length from timing either. */
export function timingSafeEqual(a, b) {
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/* ---------------- cookies ---------------- */

export function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 1) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

/* `Secure` is omitted on plain-http localhost only, so the local dev
   server works; every deployed origin is https and gets the flag. */
export function isSecureRequest(request) {
  try {
    const url = new URL(request.url);
    if (url.protocol === "https:") return true;
    if (request.headers.get("x-forwarded-proto") === "https") return true;
    return !/^(localhost|127\.0\.0\.1|\[::1\])$/i.test(url.hostname);
  } catch {
    return true;
  }
}

export function serializeCookie(name, value, opts = {}) {
  const bits = [`${name}=${encodeURIComponent(value)}`];
  bits.push(`Path=${opts.path || "/"}`);
  if (opts.maxAge !== undefined) bits.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAge))}`);
  if (opts.httpOnly) bits.push("HttpOnly");
  if (opts.secure) bits.push("Secure");
  bits.push(`SameSite=${opts.sameSite || "Lax"}`);
  return bits.join("; ");
}

/* ---------------- responses ---------------- */

export function json(body, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  for (const cookie of init.cookies || []) headers.append("set-cookie", cookie);
  return new Response(JSON.stringify(body), { status: init.status || 200, headers });
}

/* One shape for every failure the browser sees. `code` lets the front
   end react (e.g. focus a field); `message` is the text shown to the
   user. Stack traces and store errors never travel in either. */
export function fail(status, code, message, init = {}) {
  return json({ ok: false, error: { code, message } }, { ...init, status });
}
