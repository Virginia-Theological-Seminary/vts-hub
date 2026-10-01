/* ------------------------------------------------------------------
   Who is an administrator
   ------------------------------------------------------------------
   TEMPORARY DEVELOPMENT AUTHENTICATION — retires with Microsoft Entra,
   where this becomes membership of a security group and IT decides it.

   An allow-list in the environment: VTS_ADMIN_EMAILS, comma-separated.

   WHY AN ENVIRONMENT VARIABLE AND NOT A STORED ROLE
   Somebody has to be the first administrator, and every other way of
   arranging that is worse. A stored `admin` role can only be set by
   editing the database or running a command on the server — which is
   exactly the access the administration page exists to avoid needing.
   Making the first account admin would hand the site to whoever
   registered first. Reading it from the sign-up form would hand it to
   anyone who asked.

   So it is an operator's decision, made where operators already work:
   one variable in Plesk, set once. It cannot be changed from inside the
   application, which is the property that matters — an attacker who
   took over an account, or even the database, still could not make
   themselves an administrator.

   Note what this is NOT. roles.js says no address grants privilege "by
   virtue of its spelling", and that still holds: this is not a pattern
   match on the address, and nothing about being @vts.edu confers
   anything. It is a named list, written down by the person who
   administers the server.

   The address is checked against the SESSION's email, which the server
   signed, never against anything the browser sends.
   ------------------------------------------------------------------ */

import { env } from "./runtime.js";
import { normalizeEmail } from "./validation.js";

/* The configured administrators, normalised the same way stored
   addresses are, so "Nat@VTS.edu " in Plesk still matches. */
export function adminEmails() {
  return String(env("VTS_ADMIN_EMAILS", ""))
    .split(",")
    .map((entry) => normalizeEmail(entry))
    .filter(Boolean);
}

/* True only for a session the server itself issued. An empty or unset
   VTS_ADMIN_EMAILS means there are no administrators, which is the
   right default: a site nobody configured grants nobody anything. */
export function isAdminSession(session) {
  if (!session || !session.email) return false;
  const list = adminEmails();
  if (!list.length) return false;
  return list.includes(normalizeEmail(session.email));
}

/* For the startup banner, so it is obvious whether anyone can
   administer the site. Addresses, not secrets — they are already in the
   account list any administrator can read. */
export function describeAdmins() {
  const list = adminEmails();
  if (!list.length) {
    return "none — set VTS_ADMIN_EMAILS to use the administration page";
  }
  return list.join(", ");
}
