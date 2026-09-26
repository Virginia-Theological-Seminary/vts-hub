/* ------------------------------------------------------------------
   What an administrator can do
   ------------------------------------------------------------------
   TEMPORARY DEVELOPMENT AUTHENTICATION — all of this retires with
   Microsoft Entra, where accounts, invitations and forgotten passwords
   are Microsoft's business.

   One implementation of each action, shared by the two things that
   perform them: the command-line tool (account-admin.mjs) and the
   administration page (admin-api.js). Two copies would drift, and the
   one that drifted would be the one that forgot to check the sign-up
   policy before handing out a code that does nothing.

   Every function returns either

       { ok: true,  ... }
       { ok: false, code: "SOMETHING", message: "one sentence" }

   and none of them decides WHO may call it. That is the caller's job:
   admins.js for the page, having access to the server for the tool.
   ------------------------------------------------------------------ */

import {
  findUserByEmail,
  putInvite,
  updateUser,
  listUsers,
  publicUser,
} from "./user-store.js";
import { generateInviteCode, hashInviteCode } from "./invite.js";
import { generateRecoveryCode, hashRecoveryCode } from "./recovery-code.js";
import { signupPolicy } from "./providers/development-auth.js";
import { normalizeEmail, isVtsEmail, ALLOWED_EMAIL_DOMAIN } from "./validation.js";

const deny = (code, message) => ({ ok: false, code, message });

/* Every action names one address, and the rule that it must be a VTS
   one is applied here rather than four times over. */
function target(rawEmail) {
  const email = normalizeEmail(rawEmail);
  if (!email || !isVtsEmail(email)) {
    return {
      ok: false,
      error: deny(
        "EMAIL_NOT_ALLOWED",
        "That is not an @" + ALLOWED_EMAIL_DOMAIN + " address."
      ),
    };
  }
  return { ok: true, email };
}

/* ---------------- invite ---------------- */

/* Lets one named address create an account. Returns the code exactly
   once: only its hash is stored, so it cannot be produced again. */
export async function issueInvitation(rawEmail) {
  const found = target(rawEmail);
  if (!found.ok) return found.error;
  const email = found.email;

  /* A code issued while sign-up is not asking for one would do nothing
     at all, and whoever handed it over would have no way to tell. */
  const policy = await signupPolicy();
  if (!policy.invitation) {
    return deny(
      "INVITE_NOT_NEEDED",
      "Sign-up is not asking for invitations at the moment — " +
        email + " can create an account at /signup and confirm the address " +
        "from the link sent to it."
    );
  }

  if (await findUserByEmail(email)) {
    return deny(
      "ACCOUNT_EXISTS",
      email + " already has an account. Issue them a recovery code instead " +
        "if they cannot get in."
    );
  }

  const code = generateInviteCode();
  await putInvite(email, {
    codeHash: await hashInviteCode(code),
    issuedAt: new Date().toISOString(),
  });

  return { ok: true, email, code, replaced: true };
}

/* ---------------- recovery code ---------------- */

/* For somebody locked out: issues a NEW code and invalidates the old
   one. They set their own password at /reset with it, so whoever issues
   it never sees, chooses or types anyone's password. */
export async function issueRecoveryCode(rawEmail) {
  const found = target(rawEmail);
  if (!found.ok) return found.error;
  const email = found.email;

  if (!(await findUserByEmail(email))) {
    return deny("NO_ACCOUNT", "There is no account for " + email + ".");
  }

  const code = generateRecoveryCode();
  await updateUser(email, { recoveryCodeHash: await hashRecoveryCode(code) });

  return { ok: true, email, code };
}

/* ---------------- confirm by hand ---------------- */

/* For somebody who signed up while a confirmation link was required and
   never received it. Only ever done after a human has established that
   the address really is theirs — which is not something this code can
   check, and pretending otherwise would defeat the point of asking. */
export async function confirmAddress(rawEmail) {
  const found = target(rawEmail);
  if (!found.ok) return found.error;
  const email = found.email;

  const user = await findUserByEmail(email);
  if (!user) return deny("NO_ACCOUNT", "There is no account for " + email + ".");

  if (user.emailVerifiedAt && !user.verificationPending) {
    return { ok: true, email, alreadyConfirmed: true };
  }

  await updateUser(email, { emailVerifiedAt: Date.now(), verificationPending: false });
  return { ok: true, email, alreadyConfirmed: false };
}

/* ---------------- list ---------------- */

/* publicUser() on every row, so no hash can reach a response even by
   accident. `blocked` is the question an administrator is actually
   asking: who cannot sign in? */
export async function accountList() {
  const rows = await listUsers();
  const accounts = rows.map((user) => ({
    ...publicUser(user),
    blocked: Boolean(user.verificationPending && !user.emailVerifiedAt),
  }));

  accounts.sort((a, b) => String(a.email).localeCompare(String(b.email)));
  return { ok: true, accounts };
}
