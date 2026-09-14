/* ------------------------------------------------------------------
   TEMPORARY DEVELOPMENT AUTHENTICATION
   ------------------------------------------------------------------
   This authentication system is temporary and will be replaced by
   Microsoft Entra authentication for production.

   It exists so the hub can be built and demonstrated before VTS IT has
   finished the Entra app registration (README step 1). It stores its
   own accounts and checks its own passwords. It is NOT the VTS sign-in
   system, it is not connected to Microsoft 365, and an account created
   here has nothing to do with the holder's real VTS credentials.

   To remove it later: delete this file and entra-auth's sibling entry
   in auth-service.js, set AUTH_MODE=entra, and delete user-store.js,
   password.js and the two auth pages. Nothing outside the auth layer
   refers to any of it.
   ------------------------------------------------------------------ */

import {
  validateEmail,
  validatePassword,
  validatePasswordConfirmation,
  cleanName,
  MESSAGES,
} from "../validation.js";
import { hashPassword, verifyPassword, needsRehash, dummyVerify } from "../password.js";
import { findUserByEmail, createUser, updateUser, publicUser } from "../user-store.js";
import { DEFAULT_ROLE } from "../roles.js";

const deny = (field, code, message) => ({ ok: false, field, code, message });

export const developmentAuth = {
  id: "development",
  label: "VTS Hub development sign-in",
  temporary: true,
  supportsPasswordSignUp: true,
  supportsPasswordSignIn: true,

  /* ---------------- sign up ---------------- */

  async signUp(input) {
    /* Order matters: the email rule is checked first so that a non-VTS
       address is told the truth about why it was refused rather than
       being sent away to fix a password that was never the problem. */
    const email = validateEmail(input.email, "signup");
    if (!email.ok) return deny(email.field, "EMAIL_NOT_ALLOWED", email.message);

    const firstName = cleanName(input.firstName);
    const lastName = cleanName(input.lastName);
    if (!firstName || !lastName) {
      return deny("firstName", "NAME_REQUIRED", MESSAGES.NAME_REQUIRED);
    }

    const password = validatePassword(input.password);
    if (!password.ok) return deny(password.field, "PASSWORD_WEAK", password.message);

    const match = validatePasswordConfirmation(input.password, input.confirmPassword);
    if (!match.ok) return deny(match.field, "PASSWORD_MISMATCH", match.message);

    if (await findUserByEmail(email.email)) {
      return deny("email", "ACCOUNT_EXISTS", MESSAGES.DUPLICATE);
    }

    /* input.role is read nowhere. Whatever the form posts, a public
       sign-up produces DEFAULT_ROLE and nothing else. */
    const created = await createUser({
      email: email.email,
      passwordHash: await hashPassword(password.password),
      firstName,
      lastName,
      role: DEFAULT_ROLE,
    });

    if (!created.ok) return deny("email", "ACCOUNT_EXISTS", MESSAGES.DUPLICATE);

    return { ok: true, user: publicUser(created.user) };
  },

  /* ---------------- sign in ---------------- */

  async signIn(input) {
    const email = validateEmail(input.email, "login");
    if (!email.ok) return deny(email.field, "EMAIL_NOT_ALLOWED", email.message);

    const user = await findUserByEmail(email.email);

    /* No such account: spend the same time a real check would, and
       return the same message. Whether an address has an account here
       is not something an unauthenticated caller gets to learn. */
    if (!user) {
      await dummyVerify();
      return deny("password", "INVALID_CREDENTIALS", MESSAGES.CREDENTIALS);
    }

    if (!(await verifyPassword(input.password, user.passwordHash))) {
      return deny("password", "INVALID_CREDENTIALS", MESSAGES.CREDENTIALS);
    }

    /* The domain rule is re-applied to the stored record, not just to
       what was typed. If the policy ever tightens, existing accounts
       are held to the new rule at their next sign-in rather than
       being grandfathered in. */
    const stored = validateEmail(user.email, "login");
    if (!stored.ok) return deny("email", "EMAIL_NOT_ALLOWED", stored.message);

    /* Transparent upgrade if the hashing parameters have moved on. */
    if (needsRehash(user.passwordHash)) {
      try {
        await updateUser(user.email, { passwordHash: await hashPassword(input.password) });
      } catch {
        /* Not worth failing a valid sign-in over. */
      }
    }

    return { ok: true, user: publicUser(user) };
  },

  /* What the sign-in and sign-up pages need to know to render
      themselves. No secrets, no account data. */
  describe() {
    return {
      mode: "development",
      temporary: true,
      passwordSignIn: true,
      passwordSignUp: true,
      notice:
        "Temporary development sign-in. Accounts created here are for building and " +
        "testing the hub only and are not VTS Microsoft 365 accounts.",
    };
  },
};
