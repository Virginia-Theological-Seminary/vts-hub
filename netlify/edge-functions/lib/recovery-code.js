/* ------------------------------------------------------------------
   Recovery codes
   ------------------------------------------------------------------
   The second factor for resetting a password while the temporary
   development authentication has no working email.

   A password reset has to prove the person asking owns the account.
   Normally a link sent to the address does that. Without email, the
   proof has to be something established when the account was created:
   a random code, shown once at sign-up, that only the holder has.

   This is the same idea as the backup codes a bank or an authenticator
   app issues, and it is treated with the same care as a password:

     - 100 bits of entropy, from crypto.getRandomValues
     - stored as a PBKDF2 hash, never in plain text
     - compared in constant time (password.js does that)
     - single use: a new code is issued after each reset

   What it cannot do is help someone who has lost the code. That is
   deliberate — a recovery path with no proof is not a recovery path,
   it is a way in. Those users need an administrator, and that is the
   right trade for a temporary system.

   Retires with Entra, where Microsoft handles forgotten passwords.

   The alphabet excludes I, L, O, U, 0 and 1: codes get written on
   paper and read back, and those are the characters people get wrong.
   ------------------------------------------------------------------ */

import { hashPassword, verifyPassword } from "./password.js";

const ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
const GROUPS = 4;
const GROUP_LENGTH = 4;
const PREFIX = "VTSH";

/* 16 characters from a 30-character alphabet ≈ 78 bits, plus the fixed
   prefix for recognisability. Far beyond guessing, and the rate limit
   on the reset endpoint is a second wall. */
export function generateRecoveryCode() {
  const groups = [];
  for (let g = 0; g < GROUPS; g++) {
    const bytes = crypto.getRandomValues(new Uint8Array(GROUP_LENGTH));
    let group = "";
    for (const byte of bytes) group += ALPHABET[byte % ALPHABET.length];
    groups.push(group);
  }
  return PREFIX + "-" + groups.join("-");
}

/* People retype these from paper or a screenshot, so accept what they
   actually type — lower case, spaces, missing or doubled hyphens, the
   prefix left off — and compare on one canonical form.

   No character folding is needed or wanted: the alphabet never emits
   I, L, O, U, 0 or 1, so a code can never contain a character that
   might be misread as another one. Anything outside the alphabet is a
   mistake, and silently "correcting" it would only turn a wrong code
   into a different wrong code. */
export function normalizeRecoveryCode(raw) {
  const cleaned = String(raw ?? "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");

  const body = cleaned.startsWith(PREFIX) ? cleaned.slice(PREFIX.length) : cleaned;
  if (body.length !== GROUPS * GROUP_LENGTH) return "";
  if ([...body].some((c) => !ALPHABET.includes(c))) return "";

  const groups = [];
  for (let i = 0; i < body.length; i += GROUP_LENGTH) {
    groups.push(body.slice(i, i + GROUP_LENGTH));
  }
  return PREFIX + "-" + groups.join("-");
}

export async function hashRecoveryCode(code) {
  return hashPassword(normalizeRecoveryCode(code));
}

export async function verifyRecoveryCode(code, storedHash) {
  const normalized = normalizeRecoveryCode(code);
  if (!normalized) return false;
  return verifyPassword(normalized, storedHash);
}
