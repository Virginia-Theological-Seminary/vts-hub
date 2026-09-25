/* ------------------------------------------------------------------
   /api/auth/*  —  the only route the front end talks to
   ------------------------------------------------------------------
   TEMPORARY DEVELOPMENT AUTHENTICATION is what currently answers these
   routes, but the routes themselves are not temporary: they are the
   application's interface to the auth layer and stay the same when
   Microsoft Entra takes over. See lib/auth-service.js for the seam.

     GET  /api/auth/context   what the sign-in pages need to render
                              themselves, plus a CSRF token
     GET  /api/auth/session   the signed-in identity, or 401
     POST /api/auth/signup    create a development account
     POST /api/auth/login     exchange credentials for a session cookie
     POST /api/auth/logout    destroy the session
     POST /api/auth/forgot    send a password-reset link (always "ok")
     POST /api/auth/reset     redeem a reset link with a new password
     POST /api/auth/resend    send the email-confirmation link again
     POST /api/auth/verify    redeem a confirmation link

   Every response is no-store JSON. No response on any path contains a
   password, a password hash, or any part of one.
   ------------------------------------------------------------------ */

import { json, fail } from "./lib/runtime.js";
import {
  provider,
  authMode,
  issueSession,
  readSession,
  clearSessionCookies,
  issueCsrfCookie,
  checkCsrf,
  describeAuth,
  publicIdentity,
  siteOrigin,
} from "./lib/auth-service.js";
import { sessionSecret } from "./lib/session-token.js";
import {
  MESSAGES,
  PASSWORD_RULES,
  ALLOWED_EMAIL_DOMAIN,
  normalizeEmail,
} from "./lib/validation.js";
import { hit, peek, clear, LIMITS, clientIp } from "./lib/rate-limit.js";

/* Bodies are tiny; anything larger is not a sign-in form. Caps the work
   an unauthenticated caller can make the function do. */
const MAX_BODY_BYTES = 4096;

async function readJsonBody(request) {
  const type = request.headers.get("content-type") || "";
  if (!type.includes("application/json")) return { ok: false };

  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) return { ok: false };

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { ok: false };
    return { ok: true, body: parsed };
  } catch {
    return { ok: false };
  }
}

/* Only a path on this site is ever accepted as a post-sign-in
   destination. "//evil.com" and "/\evil.com" are both browser-legal
   ways of leaving the site, so both are rejected along with anything
   carrying a scheme or a backslash. This is the open-redirect guard. */
export function safeNextPath(value, fallback = "/") {
  const raw = String(value ?? "");
  if (!raw.startsWith("/")) return fallback;
  if (raw.startsWith("//") || raw.startsWith("/\\")) return fallback;
  /* Backslashes and any control character: a NUL or a newline in a
     path is malformed input, and nothing legitimate sends one. */
  if (/[\\\u0000-\u001F\u007F]/.test(raw)) return fallback;
  if (/^\/[a-z0-9+.-]*:/i.test(raw)) return fallback;
  return raw;
}

/* ---------------- routes ---------------- */

async function handleContext(request) {
  const info = await describeAuth(request);
  const csrf = issueCsrfCookie(request);

  return json(
    {
      ok: true,
      ...info,
      csrfToken: csrf.token,
      /* Sent so the sign-up form shows exactly the rules the server
         enforces, instead of a second copy that can drift out of step. */
      passwordRules: PASSWORD_RULES.map((r) => ({ id: r.id, label: r.label })),
      allowedDomain: ALLOWED_EMAIL_DOMAIN,
    },
    { cookies: [csrf.cookie] }
  );
}

async function handleSession(request) {
  const session = await readSession(request);
  if (!session) {
    return fail(401, "NOT_AUTHENTICATED", MESSAGES.SESSION_REQUIRED);
  }
  return json({ ok: true, authenticated: true, user: publicIdentity(session) });
}

async function handleSignup(request, context) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const ip = clientIp(request, context);
  const gate = hit("signup:" + ip, LIMITS.SIGNUP_PER_IP);
  if (!gate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(gate.retryAfterSeconds) },
    });
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  const active = provider();
  if (!active.supportsPasswordSignUp) {
    return fail(
      400,
      "SIGNUP_NOT_SUPPORTED",
      "Accounts are managed in Microsoft 365. Please sign in with Microsoft."
    );
  }

  /* `role` is not read from the body anywhere in this call chain: the
     provider assigns the default role itself. A public form cannot ask
     for privilege. */
  const result = await active.signUp({
    email: parsed.body.email,
    password: parsed.body.password,
    confirmPassword: parsed.body.confirmPassword,
    firstName: parsed.body.firstName,
    lastName: parsed.body.lastName,
    siteOrigin: siteOrigin(request),
  });

  if (!result.ok) {
    const status =
      result.code === "ACCOUNT_EXISTS" ? 409 : result.code === "MAIL_FAILED" ? 502 : 400;
    return fail(status, result.code, result.message, {
      headers: { "x-vts-field": result.field || "" },
    });
  }

  /* No session is issued by signing up. The password is proven on the
     sign-in page, which is the only place a session is ever minted —
     there is no second session path. `next` is where the provider wants
     the browser sent: /login?created=1 when the account is usable at
     once, absent when a confirmation link has to be opened first. */
  return json(
    {
      ok: true,
      user: { email: result.user.email, role: result.user.role },
      verification: result.verification,
      message: result.message,
      delivery: result.delivery,
      next: result.next ? safeNextPath(result.next, "/login") : undefined,
    },
    { status: 201 }
  );
}

/* "Send me the confirmation link again." Same posture as forgot: the
   answer never depends on whether the address has an account. */
async function handleResend(request, context) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const ip = clientIp(request, context);
  const ipGate = hit("forgot-ip:" + ip, LIMITS.FORGOT_PER_IP);
  if (!ipGate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(ipGate.retryAfterSeconds) },
    });
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  const active = provider();
  if (!active.resendVerification || active.describe().emailVerification?.required === false) {
    return fail(400, "VERIFY_NOT_SUPPORTED", MESSAGES.SERVER);
  }

  const emailGate = hit(
    "resend:" + normalizeEmail(parsed.body.email),
    LIMITS.VERIFY_RESEND_PER_EMAIL
  );
  if (!emailGate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(emailGate.retryAfterSeconds) },
    });
  }

  const result = await active.resendVerification({
    email: parsed.body.email,
    siteOrigin: siteOrigin(request),
  });
  if (!result.ok) {
    return fail(400, result.code, result.message, {
      headers: { "x-vts-field": result.field || "" },
    });
  }
  return json({ ok: true, message: result.message, delivery: result.delivery });
}

async function handleVerify(request, context) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const ip = clientIp(request, context);
  const gate = hit("reset-ip:" + ip, LIMITS.RESET_PER_IP);
  if (!gate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(gate.retryAfterSeconds) },
    });
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  const active = provider();
  if (!active.verifyEmail) return fail(400, "VERIFY_NOT_SUPPORTED", MESSAGES.VERIFY_INVALID);

  const result = await active.verifyEmail({ token: parsed.body.token });
  if (!result.ok) {
    return fail(400, result.code, result.message, {
      headers: { "x-vts-field": result.field || "" },
    });
  }

  return json({ ok: true, message: result.message, next: "/login?verified=1" });
}

async function handleLogin(request, context) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const ip = clientIp(request, context);
  const ipGate = hit("login-ip:" + ip, LIMITS.LOGIN_PER_IP);
  if (!ipGate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(ipGate.retryAfterSeconds) },
    });
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  const active = provider();
  if (!active.supportsPasswordSignIn) {
    return fail(
      400,
      "PASSWORD_SIGNIN_DISABLED",
      "Password sign-in is disabled. Please sign in with Microsoft."
    );
  }

  /* Per-address limiting is checked before the password is verified,
     so a locked-out caller costs us no PBKDF2 work. */
  const emailKey = "login:" + normalizeEmail(parsed.body.email);
  const emailGate = peek(emailKey, LIMITS.LOGIN_PER_EMAIL);
  if (!emailGate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(emailGate.retryAfterSeconds) },
    });
  }

  const result = await active.signIn({
    email: parsed.body.email,
    password: parsed.body.password,
  });

  if (!result.ok) {
    hit(emailKey, LIMITS.LOGIN_PER_EMAIL);
    return fail(401, result.code, result.message, {
      headers: { "x-vts-field": result.field || "" },
    });
  }

  const session = await issueSession(request, result.user);
  if (!session) return fail(500, "NOT_CONFIGURED", MESSAGES.SERVER);

  /* A good password clears the failures that preceded it. */
  clear(emailKey);

  return json(
    {
      ok: true,
      user: publicIdentity(session.payload),
      next: safeNextPath(parsed.body.next, "/"),
    },
    { cookies: session.cookies }
  );
}

async function handleForgot(request, context) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const ip = clientIp(request, context);
  const ipGate = hit("forgot-ip:" + ip, LIMITS.FORGOT_PER_IP);
  if (!ipGate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(ipGate.retryAfterSeconds) },
    });
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  const active = provider();
  if (!active.supportsPasswordReset) {
    return fail(
      400,
      "RESET_NOT_SUPPORTED",
      "Passwords are managed in Microsoft 365. Use Microsoft's own password reset."
    );
  }

  /* Per-address limit, counted whether or not the address has an
     account — a limit that only counted real accounts would itself be
     a way to tell which addresses are real. */
  const emailGate = hit("forgot:" + normalizeEmail(parsed.body.email), LIMITS.FORGOT_PER_EMAIL);
  if (!emailGate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(emailGate.retryAfterSeconds) },
    });
  }

  const result = await active.requestPasswordReset({
    email: parsed.body.email,
    siteOrigin: siteOrigin(request),
  });

  if (!result.ok) {
    return fail(400, result.code, result.message, {
      headers: { "x-vts-field": result.field || "" },
    });
  }
  return json({ ok: true, message: result.message, delivery: result.delivery });
}

async function handleReset(request, context) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const ip = clientIp(request, context);
  const gate = hit("reset-ip:" + ip, LIMITS.RESET_PER_IP);
  if (!gate.allowed) {
    return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
      headers: { "retry-after": String(gate.retryAfterSeconds) },
    });
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  const active = provider();
  if (!active.supportsPasswordReset) {
    return fail(400, "RESET_NOT_SUPPORTED", MESSAGES.RESET_INVALID);
  }

  const result = await active.resetPassword({
    token: parsed.body.token,
    password: parsed.body.password,
    confirmPassword: parsed.body.confirmPassword,
  });

  if (!result.ok) {
    return fail(400, result.code, result.message, {
      headers: { "x-vts-field": result.field || "" },
    });
  }

  /* A locked-out account is unlocked by a successful reset, otherwise
     the person who just proved ownership could not sign in. */
  clear("login:" + result.email);

  /* Not signed in automatically: the new password is confirmed by
     using it, and no session is minted from a link that arrived by
     email. Any cookie this browser holds is cleared for good measure. */
  return json(
    { ok: true, message: result.message, next: "/login?reset=1" },
    { cookies: clearSessionCookies(request, { keepCsrf: true }) }
  );
}

/* Logout is deliberately forgiving: it always succeeds and always
   clears the cookies, even without a valid session or a CSRF token.
   Refusing to log someone out is not a security win. */
async function handleLogout(request) {
  return json({ ok: true, next: "/login" }, { cookies: clearSessionCookies(request) });
}

/* ---------------- entry point ---------------- */

export default async (request, context) => {
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/auth\/?/, "").replace(/\/+$/, "");
  const method = request.method.toUpperCase();

  /* Without a signing secret no session can be issued, and pretending
     otherwise would hand out cookies nothing can verify. Logout still
     works, because clearing cookies needs no secret. */
  if (!sessionSecret() && route !== "logout") {
    console.error(
      "[vts-auth] VTS_SESSION_SECRET is not set — refusing to issue sessions. " +
        "See README step 2."
    );
    if (route === "context") {
      return json({
        ok: true,
        mode: authMode(),
        configured: false,
        temporary: authMode() === "development",
        passwordSignIn: false,
        passwordSignUp: false,
        authenticated: false,
        user: null,
        microsoft: { available: false, label: "Sign in with Microsoft", status: "Coming Soon" },
        notice:
          "Sign-in is not configured on this site yet: VTS_SESSION_SECRET is missing.",
      });
    }
    return fail(503, "NOT_CONFIGURED", MESSAGES.SERVER);
  }

  try {
    /* `return await`, not `return`: without the await a rejected promise
       escapes this try/catch and the caller sees a raw failure instead of
       the one-sentence message below. */
    if (method === "GET" && route === "context") return await handleContext(request);
    if (method === "GET" && route === "session") return await handleSession(request);
    if (method === "POST" && route === "signup") return await handleSignup(request, context);
    if (method === "POST" && route === "login") return await handleLogin(request, context);
    if (method === "POST" && route === "logout") return await handleLogout(request);
    if (method === "POST" && route === "forgot") return await handleForgot(request, context);
    if (method === "POST" && route === "reset") return await handleReset(request, context);
    if (method === "POST" && route === "resend") return await handleResend(request, context);
    if (method === "POST" && route === "verify") return await handleVerify(request, context);

    const known = ["context", "session", "signup", "login", "logout", "forgot", "reset", "resend", "verify"];
    if (known.includes(route)) {
      return fail(405, "METHOD_NOT_ALLOWED", MESSAGES.SERVER);
    }
    return fail(404, "NOT_FOUND", MESSAGES.SERVER);
  } catch (err) {
    /* The detail goes to the function log; the user gets one sentence.
       Never a stack trace, never a store error, never a field name that
       reveals whether an account exists. */
    console.error("[vts-auth] unhandled error on /api/auth/" + route, err);
    return fail(500, "SERVER_ERROR", MESSAGES.SERVER);
  }
};

export const config = { path: "/api/auth/*" };
