/* ------------------------------------------------------------------
   /api/admin/*  —  the administration page's only interface
   ------------------------------------------------------------------
   TEMPORARY DEVELOPMENT AUTHENTICATION. Exists so the one person
   administering the hub can invite people and unstick accounts without
   a shell on the production server. Retires with Microsoft Entra.

     GET  /api/admin/context   whether the caller may use this page
     GET  /api/admin/accounts  every account, and who cannot sign in
     POST /api/admin/invite    let one address create an account
     POST /api/admin/code      issue a replacement recovery code
     POST /api/admin/confirm   confirm an address by hand

   HOW THIS IS GUARDED, IN ORDER
     1. a valid session cookie, verified by the server's own signature
     2. that session's address on the VTS_ADMIN_EMAILS list (admins.js)
     3. for anything that writes, the same CSRF check as /api/auth
     4. a rate limit, keyed on the administrator

   Every one of those is re-checked on every request. Nothing trusts a
   field in the body, a header, or anything the page believes about
   itself: a page is a convenience, not a control.

   No response on any path contains a password hash or a recovery-code
   hash — the account list goes through publicUser(), which picks the
   fields it returns rather than removing the ones it does not.
   ------------------------------------------------------------------ */

import { json, fail } from "./lib/runtime.js";
import { readSession, checkCsrf } from "./lib/auth-service.js";
import { isAdminSession } from "./lib/admins.js";
import {
  issueInvitation,
  issueRecoveryCode,
  confirmAddress,
  accountList,
} from "./lib/admin-actions.js";
import { MESSAGES, normalizeEmail } from "./lib/validation.js";
import { hit, LIMITS } from "./lib/rate-limit.js";

const MAX_BODY_BYTES = 2048;

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

/* 401 and 403 are deliberately different: "you are not signed in" and
   "you are signed in, and this is not for you" are different problems
   with different remedies, and neither tells an anonymous caller
   anything it could not already guess. Who IS an administrator is
   never disclosed. */
async function requireAdmin(request) {
  const session = await readSession(request);
  if (!session) {
    return { ok: false, response: fail(401, "NOT_SIGNED_IN", MESSAGES.SIGN_IN_REQUIRED) };
  }
  if (!isAdminSession(session)) {
    return {
      ok: false,
      response: fail(
        403,
        "NOT_ADMIN",
        "This page is for hub administrators. Your account is not one."
      ),
    };
  }
  return { ok: true, session };
}

/* Writes only. A rate limit on an authenticated administrator is not
   about attackers so much as a stuck script, but the ceiling belongs
   here rather than nowhere. */
function gate(session) {
  const result = hit("admin:" + normalizeEmail(session.email), LIMITS.ADMIN_ACTIONS);
  if (result.allowed) return null;
  return fail(429, "RATE_LIMITED", MESSAGES.RATE_LIMIT, {
    headers: { "retry-after": String(result.retryAfterSeconds) },
  });
}

/* The action's own refusal, turned into a response. 400 throughout:
   these are all "that address will not do", not failures of authority,
   which were settled before we got here. */
function answer(result) {
  if (result.ok) return json(result);
  return fail(400, result.code, result.message);
}

async function write(request, session, action) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return fail(403, "CSRF", csrf.message);

  const limited = gate(session);
  if (limited) return limited;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return fail(400, "BAD_REQUEST", MESSAGES.SERVER);

  return answer(await action(parsed.body.email));
}

export default async (request, context) => {
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/admin\/?/, "").replace(/\/+$/, "");
  const method = request.method.toUpperCase();

  try {
    const guard = await requireAdmin(request);
    if (!guard.ok) return guard.response;
    const { session } = guard;

    if (method === "GET" && route === "context") {
      return json({ ok: true, admin: true, email: session.email });
    }
    if (method === "GET" && route === "accounts") {
      return json(await accountList());
    }
    if (method === "POST" && route === "invite") {
      return await write(request, session, issueInvitation);
    }
    if (method === "POST" && route === "code") {
      return await write(request, session, issueRecoveryCode);
    }
    if (method === "POST" && route === "confirm") {
      return await write(request, session, confirmAddress);
    }

    const known = ["context", "accounts", "invite", "code", "confirm"];
    if (known.includes(route)) return fail(405, "METHOD_NOT_ALLOWED", MESSAGES.SERVER);
    return fail(404, "NOT_FOUND", MESSAGES.SERVER);
  } catch (err) {
    console.error("[vts-admin] unhandled error on /api/admin/" + route, err);
    return fail(500, "SERVER_ERROR", MESSAGES.SERVER);
  }
};

export const config = { path: "/api/admin/*" };
