/* ------------------------------------------------------------------
   Validation — the authoritative copy
   ------------------------------------------------------------------
   Every rule here runs on the server. The browser imports the same
   messages for friendliness, but nothing in the browser is trusted:
   the checks below are re-run on each request before any account is
   created or any session is issued.
   ------------------------------------------------------------------ */

/* The one domain permitted to hold a VTS Hub account. When Entra
   replaces the temporary auth this stays the second gate, exactly as
   it already is in session.js and protect-files.js. */
export const ALLOWED_EMAIL_DOMAIN = "vts.edu";

export const MESSAGES = {
  SIGNUP_DOMAIN:
    "Only VTS email addresses ending in @vts.edu are allowed to create a VTS Hub account.",
  LOGIN_DOMAIN: "Only VTS email addresses are permitted to access VTS Hub.",
  EMAIL_REQUIRED: "Please enter your VTS email address.",
  EMAIL_MALFORMED: "Only VTS email addresses ending in @vts.edu are allowed.",
  CREDENTIALS: "The email or password is incorrect.",
  DUPLICATE:
    "An account with this VTS email already exists. Please sign in instead.",
  MISMATCH: "Passwords do not match.",
  PASSWORD_REQUIRED: "Please choose a password.",
  NAME_REQUIRED: "Please enter your first and last name.",
  SERVER: "We couldn't complete your request right now. Please try again.",
  RATE_LIMIT: "Too many attempts. Please wait a few minutes and try again.",
  SESSION_REQUIRED: "Please sign in to continue.",
  CSRF: "Your session expired while this page was open. Please reload and try again.",
  /* Said whether or not the address has an account, so the form cannot
     be used to find out which addresses do. */
  RESET_REQUESTED:
    "If an account exists for that address, a password reset link has been sent. " +
    "It expires in 30 minutes.",
  RESET_INVALID:
    "This password reset link is invalid or has expired. Please request a new one.",
  RESET_DONE: "Your password has been updated. Please sign in with your new password.",
  /* Shown on the sign-in page after a successful sign-up, while email
     verification is disabled for the temporary development auth. */
  ACCOUNT_CREATED:
    "Your VTS Hub account has been created successfully. Please sign in.",
  VERIFY_SENT:
    "Check your email. We've sent a link to confirm your address; it expires in 24 hours.",
  VERIFY_RESENT:
    "If an account exists for that address and is not yet confirmed, a new link has been sent.",
  VERIFY_INVALID:
    "This confirmation link is invalid or has expired. Sign in to request a new one.",
  VERIFY_DONE: "Your email address is confirmed. Please sign in.",
  EMAIL_UNVERIFIED:
    "Please confirm your email address first. Check your inbox for the link, or request a new one below.",
  MAIL_FAILED:
    "We couldn't send the confirmation email right now. Please try again in a few minutes.",
};

/* Password policy, stated once so the sign-up form can render exactly
   what the server enforces. A special character is required: there are
   no legacy accounts to grandfather, so the stricter rule costs nothing. */
export const PASSWORD_RULES = [
  { id: "length", label: "At least 8 characters", short: "at least 8 characters", test: (v) => v.length >= 8 },
  { id: "upper", label: "One uppercase letter (A-Z)", short: "an uppercase letter", test: (v) => /[A-Z]/.test(v) },
  { id: "lower", label: "One lowercase letter (a-z)", short: "a lowercase letter", test: (v) => /[a-z]/.test(v) },
  { id: "number", label: "One number (0-9)", short: "a number", test: (v) => /[0-9]/.test(v) },
  {
    id: "special",
    label: "One special character (e.g. ! ? @ # $ %)",
    short: "a special character",
    test: (v) => /[^A-Za-z0-9]/.test(v),
  },
];

/* Upper bound so a multi-megabyte body cannot be turned into a
   PBKDF2 denial-of-service. */
export const PASSWORD_MAX_LENGTH = 200;

/* Deliberately conservative: one @, no whitespace, a dot-separated
   host. Anything exotic is rejected rather than guessed at. */
const EMAIL_SHAPE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

/* trim -> strip zero-width and surrounding quotes -> lowercase.
   Lowercasing is what makes "Jane.Smith@VTS.edu" and "jane.smith@vts.edu"
   the same account, on sign-up and on sign-in alike. */
export function normalizeEmail(raw) {
  return String(raw ?? "")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim()
    .replace(/^['"<]+|['">]+$/g, "")
    .trim()
    .toLowerCase();
}

/* The domain check itself. Compares the part after the FINAL "@" to the
   allowed domain rather than calling endsWith() on the whole address, so
   "a@vts.edu@gmail.com" is rejected, and so is "user@notvts.edu" and
   "user@vts.edu.evil.com". */
export function isVtsEmail(normalized) {
  if (!EMAIL_SHAPE.test(normalized)) return false;
  const at = normalized.lastIndexOf("@");
  if (at < 1) return false;
  return normalized.slice(at + 1) === ALLOWED_EMAIL_DOMAIN;
}

/* `context` picks the wording: sign-up explains the account rule,
   sign-in explains the access rule. Both refuse the request. */
export function validateEmail(raw, context = "signup") {
  const email = normalizeEmail(raw);
  const domainMessage =
    context === "login" ? MESSAGES.LOGIN_DOMAIN : MESSAGES.SIGNUP_DOMAIN;

  if (!email) return { ok: false, field: "email", message: MESSAGES.EMAIL_REQUIRED };
  if (email.length > 254) return { ok: false, field: "email", message: domainMessage };
  if (!EMAIL_SHAPE.test(email))
    return { ok: false, field: "email", message: MESSAGES.EMAIL_MALFORMED };
  if (!isVtsEmail(email)) return { ok: false, field: "email", message: domainMessage };

  return { ok: true, email };
}

/* "a, b and c" rather than "a, b, c" — this string is read by a person. */
function listPhrase(items) {
  if (items.length <= 1) return items[0] || "";
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
}

export function validatePassword(raw) {
  const password = String(raw ?? "");
  if (!password) return { ok: false, field: "password", message: MESSAGES.PASSWORD_REQUIRED };
  if (password.length > PASSWORD_MAX_LENGTH) {
    return {
      ok: false,
      field: "password",
      message: "Please choose a password shorter than " + PASSWORD_MAX_LENGTH + " characters.",
    };
  }

  const unmet = PASSWORD_RULES.filter((r) => !r.test(password));
  if (unmet.length) {
    return {
      ok: false,
      field: "password",
      message:
        "Your password needs " + listPhrase(unmet.map((r) => r.short)) + ".",
      unmet: unmet.map((r) => r.id),
    };
  }
  return { ok: true, password };
}

export function validatePasswordConfirmation(password, confirmation) {
  if (String(password ?? "") !== String(confirmation ?? "")) {
    return { ok: false, field: "confirmPassword", message: MESSAGES.MISMATCH };
  }
  return { ok: true };
}

/* Names are display-only, but they are still bounded and stripped of
   control characters before they are stored or put in a session. */
export function cleanName(raw, max = 60) {
  return String(raw ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}
