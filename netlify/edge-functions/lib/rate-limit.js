/* ------------------------------------------------------------------
   Brute-force limiting
   ------------------------------------------------------------------
   A fixed-window counter kept in the isolate's memory. Being honest
   about what that is worth: edge isolates are short-lived and there are
   many of them, so this raises the cost of guessing a password rather
   than making it impossible. It stops the obvious thing — a script
   hammering one address from one client — which is what the brief asks
   for, and it costs no infrastructure.

   If this were to become the permanent system it would want a shared
   counter (Netlify Blobs or a rate-limiting service). It is not: Entra
   brings Microsoft's own protection, including smart lockout, and this
   module retires with the rest of the temporary auth.
   ------------------------------------------------------------------ */

const buckets = new Map();

/* Bound the map so a flood of distinct keys cannot grow it without
   limit. Oldest windows are dropped first. */
const MAX_KEYS = 5000;

function prune(now) {
  if (buckets.size <= MAX_KEYS) return;
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
    if (buckets.size <= MAX_KEYS * 0.8) break;
  }
}

/* Counts an attempt and reports whether it is allowed. */
export function hit(key, { limit, windowMs }) {
  const now = Date.now();
  let bucket = buckets.get(key);

  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }

  bucket.count += 1;
  prune(now);

  const allowed = bucket.count <= limit;
  return {
    allowed,
    remaining: Math.max(0, limit - bucket.count),
    retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
  };
}

/* Reads the window without counting against it. Used before a password
   is checked, so that a locked-out caller is refused without spending
   210,000 PBKDF2 iterations on them. */
export function peek(key, { limit }) {
  const bucket = buckets.get(key);
  const now = Date.now();
  if (!bucket || bucket.resetAt <= now) return { allowed: true, retryAfterSeconds: 0 };
  return {
    allowed: bucket.count < limit,
    retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
  };
}

/* Called after a successful sign-in so that one good password clears
   the failures that preceded it. */
export function clear(key) {
  buckets.delete(key);
}

export const LIMITS = {
  /* Failed sign-ins, counted per address. Generous enough that a person
     mistyping their password never notices it. */
  LOGIN_PER_EMAIL: { limit: 8, windowMs: 15 * 60 * 1000 },
  /* A backstop against a flood from one source, deliberately loose: the
     seminary's traffic leaves through a small number of addresses, so a
     tight per-IP figure would lock out the whole campus to slow one
     attacker. Per-address limiting above is the control that matters. */
  LOGIN_PER_IP: { limit: 200, windowMs: 15 * 60 * 1000 },
  /* Account creation, per client address — same reasoning. */
  SIGNUP_PER_IP: { limit: 30, windowMs: 60 * 60 * 1000 },
};

/* Netlify sets x-nf-client-connection-ip; the others are fallbacks for
   the local dev server. Only the first hop of x-forwarded-for is used,
   and it is never echoed back to the client. */
export function clientIp(request, context) {
  return (
    context?.ip ||
    request.headers.get("x-nf-client-connection-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
    "unknown"
  );
}

export function __resetRateLimits() {
  buckets.clear();
}
