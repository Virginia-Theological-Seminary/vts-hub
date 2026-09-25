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
import {
  findUserByEmail,
  createUser,
  updateUser,
  publicUser,
  deleteUser,
  putToken,
  takeToken,
} from "../user-store.js";
import { DEFAULT_ROLE } from "../roles.js";
import { sendMail, mailDelivery } from "../mailer.js";
import { randomId, sha256Hex } from "../runtime.js";

const deny = (field, code, message) => ({ ok: false, field, code, message });

/* How long each kind of link stays valid. A reset link is a credential
   for as long as it lives, so it is short. A confirmation link only
   proves inbox access for an account that cannot yet do anything, so
   it can be generous. */
const RESET_TOKEN_MINUTES = 30;
const VERIFY_TOKEN_HOURS = 24;

/* Mints a one-time token for `email`, stores its hash, and mails the
   link. Shared by sign-up, "send it again", and forgot-password. */
async function sendLink({ user, purpose, path, siteOrigin, subject, body, ttlMs }) {
  const token = randomId(32);
  await putToken(await sha256Hex(token), {
    email: user.email,
    purpose,
    expiresAt: Date.now() + ttlMs,
  });
  const link = siteOrigin + path + "?token=" + encodeURIComponent(token);
  await sendMail({ to: user.email, subject, text: body(link) });
}

function verificationMail(user, siteOrigin) {
  return {
    user,
    purpose: "verify",
    path: "/verify",
    siteOrigin,
    ttlMs: VERIFY_TOKEN_HOURS * 3600 * 1000,
    subject: "Confirm your VTS Hub email address",
    body: (link) =>
      "Hello " + (user.firstName || "") + ",\n\n" +
      "Thanks for creating a VTS Hub account. Confirm that this is your address by " +
      "opening this link within " + VERIFY_TOKEN_HOURS + " hours:\n\n" +
      link + "\n\n" +
      "If you did not create this account, ignore this message and it will not be " +
      "activated.\n",
  };
}

export const developmentAuth = {
  id: "development",
  label: "VTS Hub development sign-in",
  temporary: true,
  supportsPasswordSignUp: true,
  supportsPasswordSignIn: true,
  supportsPasswordReset: true,

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

    /* The account exists but cannot sign in until the holder opens the
       link. If the mail cannot be sent, the half-made account is removed
       again: it could not be used, and leaving it would occupy the
       address — the next attempt would be told "an account already
       exists, please sign in instead", which is advice that leads
       nowhere. Removing it makes "please try again" true. */
    try {
      await sendLink(verificationMail(created.user, input.siteOrigin));
    } catch (err) {
      console.error("[vts-auth] verification mail failed for a new account", err);
      try {
        await deleteUser(created.user.email);
      } catch (cleanupError) {
        /* Worth knowing about, but the sign-up has already failed and
           the message to the user does not change. */
        console.error("[vts-auth] could not remove the unsent account", cleanupError);
      }
      return deny("email", "MAIL_FAILED", MESSAGES.MAIL_FAILED);
    }

    return {
      ok: true,
      user: publicUser(created.user),
      verification: "sent",
      message: MESSAGES.VERIFY_SENT,
      delivery: mailDelivery(),
    };
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

    /* Only after the password is right, so an unverified account is not
       revealed to anyone who cannot already sign in to it. */
    if (!user.emailVerifiedAt) {
      return deny("email", "EMAIL_UNVERIFIED", MESSAGES.EMAIL_UNVERIFIED);
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

  /* ---------------- email verification ---------------- */

  /* Same shape as requestPasswordReset(): the response never depends
     on whether the address has an account, or on whether it is already
     confirmed. Only whether a message is sent does. */
  async resendVerification({ email: rawEmail, siteOrigin }) {
    const email = validateEmail(rawEmail, "login");
    if (!email.ok) return deny(email.field, "EMAIL_NOT_ALLOWED", email.message);

    const user = await findUserByEmail(email.email);
    if (user && !user.emailVerifiedAt) {
      try {
        await sendLink(verificationMail(user, siteOrigin));
      } catch (err) {
        console.error("[vts-auth] verification mail failed on resend", err);
      }
    }
    return { ok: true, message: MESSAGES.VERIFY_RESENT, delivery: mailDelivery() };
  },

  /* Redeems a confirmation link. */
  async verifyEmail({ token }) {
    const tokenValue = String(token ?? "");
    if (!tokenValue || tokenValue.length > 200) {
      return deny("token", "VERIFY_INVALID", MESSAGES.VERIFY_INVALID);
    }

    const record = await takeToken(await sha256Hex(tokenValue), "verify");
    if (!record) return deny("token", "VERIFY_INVALID", MESSAGES.VERIFY_INVALID);

    const user = await findUserByEmail(record.email);
    if (!user) return deny("token", "VERIFY_INVALID", MESSAGES.VERIFY_INVALID);

    if (!user.emailVerifiedAt) {
      await updateUser(user.email, { emailVerifiedAt: Date.now() });
    }
    return { ok: true, email: user.email, message: MESSAGES.VERIFY_DONE };
  },

  /* ---------------- forgot password ---------------- */

  /* Always succeeds from the caller's point of view. Whether the address
     has an account decides only whether a message is sent — never what
     the response says — so the form cannot be used to enumerate
     accounts. The domain rule is the exception, and it gives nothing
     away: everyone already knows only @vts.edu is admitted. */
  async requestPasswordReset({ email: rawEmail, siteOrigin }) {
    const email = validateEmail(rawEmail, "login");
    if (!email.ok) return deny(email.field, "EMAIL_NOT_ALLOWED", email.message);

    const user = await findUserByEmail(email.email);
    if (!user) {
      return { ok: true, message: MESSAGES.RESET_REQUESTED, delivery: mailDelivery() };
    }

    /* A mail failure is logged, not surfaced: the answer must be the
       same for every address, and "the provider is down" is an
       operations problem, not something to tell an unauthenticated
       caller about one specific account. */
    try {
      await sendLink({
        user,
        purpose: "reset",
        path: "/reset",
        siteOrigin,
        ttlMs: RESET_TOKEN_MINUTES * 60 * 1000,
        subject: "Reset your VTS Hub password",
        body: (link) =>
          "Hello " + (user.firstName || "") + ",\n\n" +
          "Someone asked to reset the password for your VTS Hub account. If that was " +
          "you, open this link within " + RESET_TOKEN_MINUTES + " minutes:\n\n" +
          link + "\n\n" +
          "If it was not you, ignore this message \u2014 your password has not changed.\n",
      });
    } catch (err) {
      console.error("[vts-auth] reset mail failed", err);
    }

    return { ok: true, message: MESSAGES.RESET_REQUESTED, delivery: mailDelivery() };
  },

  /* Redeems a link. The token is looked up by its hash and consumed on
     the way — one link, one attempt at a valid password. */
  async resetPassword({ token, password: rawPassword, confirmPassword }) {
    const tokenValue = String(token ?? "");
    if (!tokenValue || tokenValue.length > 200) {
      return deny("token", "RESET_INVALID", MESSAGES.RESET_INVALID);
    }

    /* Validate the new password BEFORE consuming the token, so a typo
       does not burn the link and send the user back to the start. */
    const password = validatePassword(rawPassword);
    if (!password.ok) return deny(password.field, "PASSWORD_WEAK", password.message);

    const match = validatePasswordConfirmation(rawPassword, confirmPassword);
    if (!match.ok) return deny(match.field, "PASSWORD_MISMATCH", match.message);

    const record = await takeToken(await sha256Hex(tokenValue), "reset");
    if (!record) return deny("token", "RESET_INVALID", MESSAGES.RESET_INVALID);

    const user = await findUserByEmail(record.email);
    if (!user) return deny("token", "RESET_INVALID", MESSAGES.RESET_INVALID);

    /* passwordChangedAt is what lets readSession() refuse any session
       issued before this moment — including one held by whoever made
       the reset necessary. */
    /* Opening a reset link proves the same thing a confirmation link
       does — that this person reads mail at this address — so an
       unconfirmed account is confirmed by it. */
    await updateUser(user.email, {
      passwordHash: await hashPassword(password.password),
      passwordChangedAt: Date.now(),
      emailVerifiedAt: user.emailVerifiedAt || Date.now(),
    });

    return { ok: true, email: user.email, message: MESSAGES.RESET_DONE };
  },

  /* What the sign-in and sign-up pages need to know to render
      themselves. No secrets, no account data. */
  describe() {
    return {
      mode: "development",
      temporary: true,
      passwordSignIn: true,
      passwordSignUp: true,
      passwordReset: { available: true, delivery: mailDelivery() },
      emailVerification: { required: true, delivery: mailDelivery() },
      notice:
        "Temporary development sign-in. Accounts created here are for building and " +
        "testing the hub only and are not VTS Microsoft 365 accounts.",
    };
  },
};
