/* ------------------------------------------------------------------
   Password hashing
   ------------------------------------------------------------------
   PBKDF2-HMAC-SHA-256, 210,000 iterations (the OWASP figure for this
   algorithm), 16-byte random salt, 32-byte derived key.

   Why not Argon2id or bcrypt, which are the stronger algorithms: both
   need a native or WASM module. The Netlify Edge runtime could only get
   one by pulling it from a third-party CDN at request time, and this
   project deliberately vendors everything and has no external runtime
   dependencies. PBKDF2-SHA-256 is available natively through Web
   Crypto, is FIPS-approved, and at this iteration count is a sound
   choice for the temporary development accounts it protects.

   The stored string carries its own algorithm and cost:

       pbkdf2-sha256$210000$<salt>$<hash>

   so needsRehash() can spot older parameters and a record can be
   upgraded transparently on the next successful sign-in — which is
   also the migration path if Argon2 becomes available later.

   Plaintext passwords are never stored, never logged, and never leave
   this module.
   ------------------------------------------------------------------ */

import { b64url, unb64url, encode, timingSafeEqual } from "./runtime.js";

const ALGORITHM = "pbkdf2-sha256";
const ITERATIONS = 210000;
const SALT_BYTES = 16;
const KEY_BITS = 256;

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    KEY_BITS
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(password, salt, ITERATIONS);
  return ALGORITHM + "$" + ITERATIONS + "$" + b64url(salt) + "$" + b64url(hash);
}

/* Returns a plain boolean and swallows malformed records — a corrupt
   stored hash must read as "wrong password", never as an exception an
   attacker could tell apart from a wrong password. */
export async function verifyPassword(password, stored) {
  try {
    const parts = String(stored ?? "").split("$");
    if (parts.length !== 4) return false;
    const [algorithm, iterationsRaw, saltRaw, hashRaw] = parts;
    if (algorithm !== ALGORITHM) return false;

    const iterations = Number.parseInt(iterationsRaw, 10);
    if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 5000000) return false;

    const salt = unb64url(saltRaw);
    const expected = unb64url(hashRaw);
    const actual = await derive(String(password ?? ""), salt, iterations);
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function needsRehash(stored) {
  const parts = String(stored ?? "").split("$");
  if (parts[0] !== ALGORITHM) return true;
  return Number.parseInt(parts[1], 10) < ITERATIONS;
}

/* Burns roughly the same time as a real verification. Called when the
   email does not exist, so "no such account" and "wrong password" take
   the same wall-clock time and cannot be told apart. */
export async function dummyVerify() {
  const salt = new Uint8Array(SALT_BYTES);
  await derive("timing-equalisation-placeholder", salt, ITERATIONS);
  return false;
}
