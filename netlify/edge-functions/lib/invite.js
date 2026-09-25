/* ------------------------------------------------------------------
   Invitations
   ------------------------------------------------------------------
   What proves a sign-up is a real VTS person, while there is neither
   working email nor Microsoft Entra.

   THE PROBLEM THIS SOLVES
   The @vts.edu rule checks the shape of an address, not that the person
   typing it owns it. Without a confirmation mail, anyone could register
   dean@vts.edu and be inside. An invitation moves the proof to where it
   can actually happen: an administrator who knows who they are talking
   to issues a code for one named address, out of band.

   HOW IT IS BOUND
   An invitation is stored against the address it was issued for, so a
   code that leaks cannot be used to register anything else. The code
   itself is never stored — only its hash, alongside the address — so a
   copy of the database yields no usable invitations.

   Single use: redeeming it removes it.

   Retires with Entra, which authenticates against the real VTS account
   and makes every part of this unnecessary.
   ------------------------------------------------------------------ */

import { sha256Hex } from "./runtime.js";
/* The password primitives directly, not the recovery-code helpers:
   those normalise to the VTSH shape, so an invitation would never
   verify through them. */
import { hashPassword, verifyPassword } from "./password.js";

/* Same alphabet and shape as a recovery code, so both read as "a VTS
   code", but a different prefix and half the length: an invitation is
   short-lived and typed once, where a recovery code is kept. */
const PREFIX = "VTSI";
const ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
const GROUPS = 2;
const GROUP_LENGTH = 4;

export function generateInviteCode() {
  const groups = [];
  for (let g = 0; g < GROUPS; g++) {
    const bytes = crypto.getRandomValues(new Uint8Array(GROUP_LENGTH));
    let group = "";
    for (const byte of bytes) group += ALPHABET[byte % ALPHABET.length];
    groups.push(group);
  }
  return PREFIX + "-" + groups.join("-");
}

export function normalizeInviteCode(raw) {
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

/* Keyed by the address, not the code: an administrator issuing a second
   invitation for someone replaces the first rather than leaving two
   live, and redeeming looks up by the address that was typed. */
export const inviteKeyFor = async (email) => "invite:" + (await sha256Hex("invite:" + email)).slice(0, 40);

export async function hashInviteCode(code) {
  return hashPassword(normalizeInviteCode(code));
}

export async function verifyInviteCode(code, storedHash) {
  const normalized = normalizeInviteCode(code);
  if (!normalized) return false;
  return verifyPassword(normalized, storedHash);
}
