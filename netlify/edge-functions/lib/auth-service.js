/* ------------------------------------------------------------------
   Auth service — the seam
   ------------------------------------------------------------------
       VTS Hub
          |
          v
       Auth Service            <- everything else talks to this
          |
          +-- DevelopmentAuth      (temporary, in use now)
          |
          +-- MicrosoftEntraAuth   (production, not yet switched on)

   The rest of the site knows about sessions, identities and roles. It
   does not know how a password is checked, where accounts are kept, or
   which provider answered — none of that appears in any page, any route
   guard, or any response body.

   Swapping providers is therefore one environment variable:

       AUTH_MODE=development   (default)
       AUTH_MODE=entra

   Session issuing, cookie policy and the domain rule live HERE rather
   than in either provider, because they are the same under both. That
   is what makes the swap cheap: a provider only has to answer "is this
   person who they say they are, and who are they".
   ------------------------------------------------------------------ */

import { developmentAuth } from "./providers/development-auth.js";
import { microsoftEntraAuth } from "./providers/entra-auth.js";
import {
  env,
  serializeCookie,
  isSecureRequest,
  parseCookies,
  randomId,
  timingSafeEqual,
  encode,
} from "./runtime.js";
import {
  SESSION_COOKIE,
  CSRF_COOKIE,
  CSRF_HEADER,
  SESSION_HOURS,
  sessionSecret,
  signSession,
  verifySession,
  sessionPayload,
  publicIdentity,
} from "./session-token.js";
import { MESSAGES } from "./validation.js";

const PROVIDERS = {
  development: developmentAuth,
  entra: microsoftEntraAuth,
};

export function authMode() {
  const mode = String(env("AUTH_MODE", "development")).toLowerCase();
  return PROVIDERS[mode] ? mode : "development";
}

export function provider() {
  return PROVIDERS[authMode()];
}

/* ---------------- sessions ---------------- */

export async function issueSession(request, user) {
  const secret = sessionSecret();
  if (!secret) return null;

  /* A brand-new payload with a brand-new session id on every sign-in.
     Any cookie the caller arrived holding is replaced, never adopted —
     session fixation has nothing to fix onto. */
  const payload = sessionPayload(user, authMode());
  const token = await signSession(payload, secret);
  const secure = isSecureRequest(request);

  return {
    payload,
    cookies: [
      serializeCookie(SESSION_COOKIE, token, {
        httpOnly: true,
        secure,
        /* Lax, not Strict: document links under /files/ are ordinary
           top-level navigations and must carry the cookie. Lax sends it
           for those and withholds it from cross-site POSTs, which is
           exactly the split we want. */
        sameSite: "Lax",
        maxAge: SESSION_HOURS * 3600,
      }),
      /* Readable by script on purpose — the double-submit half of the
         CSRF check. It authorises nothing on its own. */
      serializeCookie(CSRF_COOKIE, randomId(16), {
        httpOnly: false,
        secure,
        sameSite: "Lax",
        maxAge: SESSION_HOURS * 3600,
      }),
    ],
  };
}

export async function readSession(request) {
  const secret = sessionSecret();
  if (!secret) return null;
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;
  return verifySession(token, secret);
}

/* Expiring both cookies with Max-Age=0 is what actually ends the
   session: the token is stateless, so the browser has to be told to
   discard it. Same attributes as when they were set, or the browser
   keeps the originals alongside the blanks. */
export function clearSessionCookies(request) {
  const secure = isSecureRequest(request);
  return [
    serializeCookie(SESSION_COOKIE, "", { httpOnly: true, secure, sameSite: "Lax", maxAge: 0 }),
    serializeCookie(CSRF_COOKIE, "", { httpOnly: false, secure, sameSite: "Lax", maxAge: 0 }),
  ];
}

export function issueCsrfCookie(request) {
  const token = randomId(16);
  return {
    token,
    cookie: serializeCookie(CSRF_COOKIE, token, {
      httpOnly: false,
      secure: isSecureRequest(request),
      sameSite: "Lax",
      maxAge: SESSION_HOURS * 3600,
    }),
  };
}

/* ---------------- request protection ---------------- */

/* Two independent checks, both cheap:
     1. Origin (or Referer) must be this site. Browsers set Origin on
        every cross-site POST and page script cannot forge it.
     2. Double-submit: the header must equal the cookie. A cross-site
        page can cause the cookie to be sent but cannot read it, so it
        cannot produce the matching header. */
export function checkCsrf(request) {
  const url = new URL(request.url);
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  const source = origin || referer;

  if (source) {
    try {
      if (new URL(source).host !== url.host) return { ok: false, message: MESSAGES.CSRF };
    } catch {
      return { ok: false, message: MESSAGES.CSRF };
    }
  }

  const cookie = parseCookies(request)[CSRF_COOKIE];
  const header = request.headers.get(CSRF_HEADER);
  if (!cookie || !header || !timingSafeEqual(encode(cookie), encode(header))) {
    return { ok: false, message: MESSAGES.CSRF };
  }
  return { ok: true };
}

/* ---------------- what the browser is told ---------------- */

export async function describeAuth(request) {
  const active = provider();
  const session = await readSession(request);

  return {
    ...active.describe(),
    configured: Boolean(sessionSecret()),
    /* The Microsoft button is live only under the entra provider. In
       development it renders disabled and "Coming Soon", and the server
       agrees: microsoftEntraAuth refuses every password path, and no
       route here will start a Microsoft flow. */
    microsoft: {
      available: active.id === "entra",
      label: "Sign in with Microsoft",
      status: active.id === "entra" ? null : "Coming Soon",
      help:
        active.id === "entra"
          ? null
          : "Microsoft Entra authentication is currently being configured by the VTS development team.",
    },
    authenticated: Boolean(session),
    user: publicIdentity(session),
  };
}

export { publicIdentity };
