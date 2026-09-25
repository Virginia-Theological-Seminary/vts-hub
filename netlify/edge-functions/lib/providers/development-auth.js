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
  findInvite,
  takeInvite,
} from "../user-store.js";
import { DEFAULT_ROLE } from "../roles.js";
import { sendMail, mailDelivery, mailCapability } from "../mailer.js";
import {
  generateRecoveryCode,
  hashRecoveryCode,
  verifyRecoveryCode,
} from "../recovery-code.js";
import { verifyInviteCode } from "../invite.js";
import { env, randomId, sha256Hex } from "../runtime.js";

const deny = (field, code, message) => ({ ok: false, field, code, message });

/* ------------------------------------------------------------------
   HOW SIGN-UP PROVES THE ADDRESS BELONGS TO THE PERSON
   ------------------------------------------------------------------
   The @vts.edu rule can only check the SHAPE of an address. On its own
   it would let anyone register dean@vts.edu and be inside. Something
   has to supply the missing proof, and there are two ways to do it:

     "email"       a confirmation link. The account cannot sign in
                   until it is opened, so the holder must be able to
                   read mail at the address. This is the simple, strong
                   one — only VTS IT can create an @vts.edu mailbox —
                   and it is the one we want.

     "invitation"  an administrator who knows who they are talking to
                   issues a code for one named address, out of band
                   (npm run account -- --invite). Slower, and it needs a
                   human in the loop, but it works with no mail at all.

   WHY THIS IS NOT A CONSTANT
   A confirmation link only proves anything if mail genuinely leaves the
   server. Ours does not yet: the sending domain's DNS records are not
   published, so the provider refuses every message. Requiring
   confirmation today would not make sign-up safer, it would make it
   impossible — nobody could ever finish one.

   So the policy follows the capability. The server asks the mail
   provider whether a message can reach somebody other than the mail
   account's own owner (mailCapability, in mailer.js):

       mail cannot get out  ->  invitation
       mail can get out     ->  email confirmation

   The day IT publishes those DNS records, the next restart moves to
   email confirmation by itself: no code change, no deploy, and no
   window in which sign-up is open with neither proof in force.

   An operator can pin it with VTS_SIGNUP_POLICY:

       auto         follow the mail capability (the default)
       invitation   invitation codes, whatever mail can do
       email        confirmation links, whatever mail can do

   The safe default — in force before the question has been answered,
   and whenever answering it fails — is "invitation", because it is the
   one that cannot be defeated by mail being broken.

   All of this retires with Microsoft Entra, which authenticates against
   the real VTS account and makes the question moot.

   PASSWORD RESET IS SEPARATE
   Resetting a password is always proved by RECOVERY CODE: issued once
   at sign-up, stored only as a hash, required to set a new password.
   See recovery-code.js. A reset therefore proves possession of that
   code; it does not prove ownership of the address, and is not allowed
   to stand in for it.
   ------------------------------------------------------------------ */
const POLICIES = {
  invitation: { emailVerification: false, invitation: true },
  email: { emailVerification: true, invitation: false },
};

let resolvedPolicy = {
  ...POLICIES.invitation,
  name: "invitation",
  source: "default",
  reason: "the sign-up policy has not been worked out yet",
};
let policyPending = null;

async function resolvePolicy() {
  const configured = String(env("VTS_SIGNUP_POLICY", "") || "auto").trim().toLowerCase();

  if (Object.prototype.hasOwnProperty.call(POLICIES, configured)) {
    return {
      ...POLICIES[configured],
      name: configured,
      source: "configured",
      reason: "VTS_SIGNUP_POLICY=" + configured,
    };
  }
  if (configured !== "auto") {
    console.warn(
      "[vts-auth] VTS_SIGNUP_POLICY=" + JSON.stringify(configured) +
        " is not one of auto, invitation, email — following the mail capability instead"
    );
  }

  const mail = await mailCapability();
  const name = mail.usable ? "email" : "invitation";
  return { ...POLICIES[name], name, source: "auto", reason: mail.detail };
}

/* Worked out once and remembered: every sign-up and every load of the
   sign-up page asks. Restarting re-asks, which is how newly published
   DNS records take effect. */
export async function signupPolicy() {
  if (!policyPending) {
    policyPending = resolvePolicy().then(
      (resolved) => {
        resolvedPolicy = resolved;
        return resolved;
      },
      (err) => {
        /* Staying on the safe default is the right way to fail: sign-up
           keeps working, by invitation, and a restart asks again. */
        console.error("[vts-auth] could not work out the sign-up policy", err);
        return resolvedPolicy;
      }
    );
  }
  return policyPending;
}

/* The policy as last resolved, for describe(), which is synchronous.
   Anything that must be current awaits signupPolicy() first — the
   provider's ready() exists for exactly that. */
export function currentSignupPolicy() {
  return resolvedPolicy;
}

/* How long each kind of link stays valid. A reset link is a credential
   for as long as it lives, so it is short. A confirmation link only
   proves inbox access for an account that cannot yet do anything, so
   it can be generous. */
/* Only the confirmation link has a lifetime now; password reset is
   proven by the recovery code, which does not expire. */
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

  /* Settles the sign-up policy before anything reads it. Called by the
     startup banner and by whatever answers /api/auth/context, so the
     page and the server never disagree about what sign-up asks for. */
  async ready() {
    return await signupPolicy();
  },

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

    const policy = await signupPolicy();

    /* Checked before anything is created, and answered identically
       whether no invitation exists, the code is wrong, or it was issued
       to somebody else — so this cannot be used to discover who has
       been invited. The invitation is consumed further down, only once
       the account is definitely being made. */
    if (policy.invitation) {
      if (!String(input.inviteCode ?? "").trim()) {
        return deny("inviteCode", "INVITE_REQUIRED", MESSAGES.INVITE_REQUIRED);
      }
      const invite = await findInvite(email.email);
      if (!invite || !(await verifyInviteCode(input.inviteCode, invite.codeHash))) {
        return deny("inviteCode", "INVITE_INVALID", MESSAGES.INVITE_INVALID);
      }
    }

    /* The one chance to establish a shared secret with this person.
       Shown once, never again, and only its hash is kept — so it is
       worth exactly as much as a password and is treated as one. */
    const recoveryCode = generateRecoveryCode();

    /* input.role is read nowhere. Whatever the form posts, a public
       sign-up produces DEFAULT_ROLE and nothing else. */
    const created = await createUser({
      email: email.email,
      passwordHash: await hashPassword(password.password),
      firstName,
      lastName,
      role: DEFAULT_ROLE,
      /* Under the invitation policy the account is usable at once, so
         the stored record says so, rather than "awaiting a confirmation
         that will never be asked for". */
      emailVerifiedAt: policy.emailVerification ? null : Date.now(),
      /* Records that THIS account was made under a policy that owes a
         confirmation — which is not the same as "has not confirmed".
         Accounts created before, when none was ever asked for, must not
         be locked out the day the policy changes under them. */
      verificationPending: policy.emailVerification,
      recoveryCodeHash: await hashRecoveryCode(recoveryCode),
    });

    if (!created.ok) return deny("email", "ACCOUNT_EXISTS", MESSAGES.DUPLICATE);

    /* One invitation opens one account. Removed only now, so a failure
       above leaves it usable for the retry. */
    if (policy.invitation) {
      try {
        await takeInvite(email.email);
      } catch (err) {
        console.error("[vts-auth] could not consume the invitation", err);
      }
    }

    /* Invitation policy: the account is already usable, so there is
       nothing to send and nothing to wait for. The holder goes to the
       sign-in page and proves the password they just chose. */
    if (!policy.emailVerification) {
      return {
        ok: true,
        user: publicUser(created.user),
        verification: "not-required",
        message: MESSAGES.ACCOUNT_CREATED,
        next: "/login?created=1",
        /* The only time this value exists in a response. The sign-up
           page shows it once and the server never returns it again. */
        recoveryCode,
      };
    }

    /* Verification on: the account exists but cannot sign in until the
       holder opens the link. If the mail cannot be sent, the half-made
       account is removed again — it could not be used, and leaving it
       would occupy the address, so the next attempt would be told "an
       account already exists, please sign in instead", which is advice
       that leads nowhere. Removing it makes "please try again" true. */
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
      next: "/login?created=1",
      /* Handed over even though sign-in is still blocked: this is the
         only moment it exists, and a confirmation link is not a
         substitute for it. The page shows both together. */
      recoveryCode,
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

    /* Only after the password is right, so an unconfirmed account is
       not revealed to anyone who cannot already sign in to it.

       The test is on the account, not on today's policy: a confirmation
       was asked of THIS account and has not been given. Deliberately
       not "is the policy email today", because the policy can change
       under an account either way, and neither change should silently
       let somebody in or shut somebody out.

       Anyone stuck here has two ways out: the confirmation link, sent
       again from the sign-in page, or an administrator confirming them
       by hand (npm run account -- --verify). */
    if (user.verificationPending && !user.emailVerifiedAt) {
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
    if (user && user.verificationPending && !user.emailVerifiedAt) {
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
      await updateUser(user.email, {
        emailVerifiedAt: Date.now(),
        verificationPending: false,
      });
    }
    return { ok: true, email: user.email, message: MESSAGES.VERIFY_DONE };
  },

  /* ---------------- forgot password ---------------- */

  /* Without email there is no link to send, so there is nothing to
     request: the reset page asks for the recovery code directly. This
     stays, refusing plainly, so that a stale client or an old bookmark
     gets an honest answer rather than a silent "check your email" for
     mail that will never come. */
  async requestPasswordReset({ email: rawEmail }) {
    const email = validateEmail(rawEmail, "login");
    if (!email.ok) return deny(email.field, "EMAIL_NOT_ALLOWED", email.message);
    return deny("email", "RESET_BY_CODE", MESSAGES.RESET_BY_CODE);
  },

  /* Sets a new password, proven by the recovery code issued at
     sign-up. Deliberately NOT a link: there is no email to send one to.

     The answer is the same whether the address has no account or the
     code is wrong — "the email address or recovery code is incorrect" —
     so this cannot be used to discover which addresses are registered.
     Rate limiting on the route is what makes guessing the code
     impractical on top of its own size. */
  async resetPassword({ email: rawEmail, recoveryCode, password: rawPassword, confirmPassword }) {
    const email = validateEmail(rawEmail, "login");
    if (!email.ok) return deny(email.field, "EMAIL_NOT_ALLOWED", email.message);

    /* Check the new password BEFORE the code, so a typo in the password
       does not consume the one code the person has. */
    const password = validatePassword(rawPassword);
    if (!password.ok) return deny(password.field, "PASSWORD_WEAK", password.message);

    const match = validatePasswordConfirmation(rawPassword, confirmPassword);
    if (!match.ok) return deny(match.field, "PASSWORD_MISMATCH", match.message);

    const user = await findUserByEmail(email.email);

    /* No account, or an account with no code on it (created before
       recovery codes existed): spend the same time a real check would,
       and give the same answer. */
    if (!user || !user.recoveryCodeHash) {
      await dummyVerify();
      return deny("recoveryCode", "RESET_INVALID", MESSAGES.RESET_CODE_INVALID);
    }

    if (!(await verifyRecoveryCode(recoveryCode, user.recoveryCodeHash))) {
      return deny("recoveryCode", "RESET_INVALID", MESSAGES.RESET_CODE_INVALID);
    }

    /* Single use. A fresh code is issued in the same write, so the
       holder is never left without a way back in — and a code seen over
       someone's shoulder is worthless once it has been used.

       passwordChangedAt is what lets readSession() refuse every session
       issued before this moment, including one held by whoever made the
       reset necessary. */
    const nextCode = generateRecoveryCode();
    await updateUser(user.email, {
      passwordHash: await hashPassword(password.password),
      passwordChangedAt: Date.now(),
      recoveryCodeHash: await hashRecoveryCode(nextCode),
      /* emailVerifiedAt is deliberately left alone. A recovery code
         proves possession of the code, not ownership of the mailbox;
         letting a reset confer confirmation would hand anyone who
         signed up unconfirmed a way to confirm themselves. */
    });

    return {
      ok: true,
      email: user.email,
      message: MESSAGES.RESET_DONE,
      recoveryCode: nextCode,
    };
  },

  /* What the sign-in and sign-up pages need to know to render
      themselves. No secrets, no account data. */
  describe() {
    return {
      mode: "development",
      temporary: true,
      passwordSignIn: true,
      passwordSignUp: true,
      passwordReset: { available: true, method: "recovery-code", delivery: null },
      emailVerification: {
        required: resolvedPolicy.emailVerification,
        delivery: mailDelivery(),
      },
      invitation: { required: resolvedPolicy.invitation },
      notice:
        "Temporary development sign-in. Accounts created here are for building and " +
        "testing the hub only and are not VTS Microsoft 365 accounts.",
    };
  },
};
