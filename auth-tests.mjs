/* ------------------------------------------------------------------
   Auth tests
   ------------------------------------------------------------------
   Covers the sign-up rules, the sign-in rules, sessions and logout, and
   the security properties the auth layer is supposed to have. Not
   published — only site/ is.

   Start a FRESH dev server first, then run these against it:

       node dev-server.mjs                     (terminal 1)
       PORT=8888 node auth-tests.mjs           (terminal 2)

   Fresh matters: the suite creates around a dozen accounts, and the
   sign-up rate limit is 30 per hour per address. Three runs against one
   long-lived server will trip it — which is the limiter working, not a
   failure. Restart the server between runs.

   The "password storage" and "provider swap" blocks import the auth
   modules directly rather than going through HTTP, because what they
   check — that a hash is stored and never exposed, that AUTH_MODE picks
   a different provider — is deliberately invisible from outside.
   ------------------------------------------------------------------ */

const BASE = "http://localhost:" + (process.env.PORT || 8888);

let pass = 0, fail = 0;
const failures = [];

function check(name, condition, detail) {
  if (condition) { pass++; console.log("  PASS  " + name); }
  else { fail++; failures.push(name + (detail ? "  [" + detail + "]" : "")); console.log("  FAIL  " + name + (detail ? "  -> " + detail : "")); }
}
function section(title) { console.log("\n=== " + title + " ==="); }

/* --- a browser-ish cookie jar --- */
class Client {
  constructor() { this.jar = new Map(); }
  cookieHeader() {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  absorb(response) {
    for (const raw of response.headers.getSetCookie?.() || []) {
      const [pair, ...attrs] = raw.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const maxAge = attrs.map(a => a.trim()).find(a => /^max-age=/i.test(a));
      if (maxAge && Number(maxAge.split("=")[1]) === 0) this.jar.delete(name);
      else this.jar.set(name, decodeURIComponent(value));
    }
  }
  async fetch(path, options = {}) {
    const headers = Object.assign({}, options.headers);
    const cookie = this.cookieHeader();
    if (cookie) headers.cookie = cookie;
    if (options.json !== undefined) {
      headers["content-type"] = "application/json";
      headers.origin = BASE;
      if (!("x-vts-csrf" in headers) && this.jar.has("vts_csrf")) {
        headers["x-vts-csrf"] = this.jar.get("vts_csrf");
      }
    }
    const response = await fetch(BASE + path, {
      method: options.method || (options.json !== undefined ? "POST" : "GET"),
      headers,
      body: options.json === undefined ? undefined : JSON.stringify(options.json),
      redirect: "manual",
    });
    this.absorb(response);
    let body = null;
    const text = await response.text();
    try { body = JSON.parse(text); } catch { body = text; }
    return { status: response.status, headers: response.headers, body, text };
  }
  async primeCsrf() { await this.fetch("/api/auth/context"); }
}

const strong = "Str0ng!Pass1";

/* Pulls the newest message for `email` out of the dev outbox and
   returns the token from its link, or "" if there is none. */
async function latestToken(client, email, path) {
  const outbox = (await client.fetch("/__dev/outbox?json")).body;
  const mail = [...outbox].reverse().find((m) => m.to === email && m.text.includes(path + "?token="));
  if (!mail) return "";
  const link = (/https?:\/\/\S+/.exec(mail.text) || [])[0] || "";
  try { return new URL(link).searchParams.get("token") || ""; } catch { return ""; }
}

/* Sign-up creates an unconfirmed account; this is the click on the
   confirmation link that makes it usable. */
async function confirm(client, email) {
  const token = await latestToken(client, email, "/verify");
  return client.fetch("/api/auth/verify", { json: { token } });
}

/* Addresses are scoped to this run so the suite can be run repeatedly
   against a server that is still holding the previous run's accounts. */
const RUN = Date.now().toString(36);
const at = (local) => local + "." + RUN + "@vts.edu";

/* ================= SIGNUP ================= */
section("Signup");

{
  const c = new Client();
  await c.primeCsrf();

  const ok = await c.fetch("/api/auth/signup", { json: {
    firstName: "Jane", lastName: "Smith", email: at("jane.smith"),
    password: strong, confirmPassword: strong } });

  if (ok.status === 429) {
    console.error("");
    console.error("  This server has already taken its hour's worth of sign-ups.");
    console.error("  Restart the dev server and run the suite again.");
    console.error("");
    process.exit(2);
  }
  check("valid @vts.edu signup succeeds", ok.status === 201, "status " + ok.status);
  check("signup does NOT sign the browser in (address unconfirmed)", !c.jar.has("vts_session"));
  check("signup says a confirmation link was sent",
    ok.body?.verification === "sent" && /Check your email/.test(ok.body?.message || ""),
    JSON.stringify(ok.body).slice(0, 120));
  check("signup response carries no password field",
    !/password/i.test(JSON.stringify(ok.body)), JSON.stringify(ok.body).slice(0, 120));
  check("signup response carries no token", !/token/i.test(JSON.stringify(ok.body)));
  check("signup default role is student", ok.body?.user?.role === "student", ok.body?.user?.role);

  const janeToken = await latestToken(c, at("jane.smith"), "/verify");
  check("a confirmation mail was sent to the new address", janeToken.length > 30, janeToken.slice(0, 10));

  const early = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong } });
  check("login before confirmation is refused with EMAIL_UNVERIFIED",
    early.status === 401 && early.body?.error?.code === "EMAIL_UNVERIFIED",
    early.status + " " + early.body?.error?.code);
  const earlyWrong = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: "Wrong!Pw1" } });
  check("wrong password on an unconfirmed account says nothing about confirmation",
    earlyWrong.body?.error?.code === "INVALID_CREDENTIALS", earlyWrong.body?.error?.code);

  const confirmed = await confirm(c, at("jane.smith"));
  check("confirmation link is accepted", confirmed.status === 200 && confirmed.body?.next === "/login?verified=1",
    confirmed.status + " " + JSON.stringify(confirmed.body));
  const confirmedAgain = await c.fetch("/api/auth/verify", { json: { token: janeToken } });
  check("confirmation link is single-use", confirmedAgain.status === 400 &&
    confirmedAgain.body?.error?.code === "VERIFY_INVALID", confirmedAgain.status);

  for (const [label, email] of [["Gmail", "john@gmail.com"], ["Yahoo", "user@yahoo.com"],
                                ["Outlook", "test@outlook.com"], ["Hotmail", "person@hotmail.com"],
                                ["example.com", "admin@example.com"]]) {
    const c2 = new Client(); await c2.primeCsrf();
    const r = await c2.fetch("/api/auth/signup", { json: {
      firstName: "A", lastName: "B", email, password: strong, confirmPassword: strong } });
    check(`invalid ${label} signup rejected`, r.status === 400 &&
      r.body?.error?.message === "Only VTS email addresses ending in @vts.edu are allowed to create a VTS Hub account.",
      r.status + " " + r.body?.error?.message);
  }

  {
    const c3 = new Client(); await c3.primeCsrf();
    const r = await c3.fetch("/api/auth/signup", { json: {
      firstName: "Up", lastName: "Case", email: "  " + at("student123").toUpperCase() + "  ",
      password: strong, confirmPassword: strong } });
    check("uppercase + whitespace email normalised and accepted",
      r.status === 201 && r.body?.user?.email === at("student123"),
      r.status + " " + r.body?.user?.email);
    await confirm(c3, at("student123"));
  }

  {
    const c4 = new Client(); await c4.primeCsrf();
    const r = await c4.fetch("/api/auth/signup", { json: {
      firstName: "W", lastName: "P", email: at("weak"),
      password: "weak", confirmPassword: "weak" } });
    check("weak password rejected", r.status === 400 && r.body?.error?.code === "PASSWORD_WEAK",
      r.status + " " + r.body?.error?.code);
  }

  {
    const c5 = new Client(); await c5.primeCsrf();
    const r = await c5.fetch("/api/auth/signup", { json: {
      firstName: "M", lastName: "M", email: at("mismatch"),
      password: strong, confirmPassword: strong + "x" } });
    check("mismatched password rejected with exact message",
      r.status === 400 && r.body?.error?.message === "Passwords do not match.",
      r.status + " " + r.body?.error?.message);
  }

  {
    const c6 = new Client(); await c6.primeCsrf();
    const r = await c6.fetch("/api/auth/signup", { json: {
      firstName: "Jane", lastName: "Smith", email: at("jane.smith").toUpperCase(),
      password: strong, confirmPassword: strong } });
    check("duplicate account rejected (409, case-insensitive)",
      r.status === 409 && r.body?.error?.message ===
        "An account with this VTS email already exists. Please sign in instead.",
      r.status + " " + r.body?.error?.message);
  }

  {
    const c7 = new Client(); await c7.primeCsrf();
    const r = await c7.fetch("/api/auth/signup", { json: {
      firstName: "Priv", lastName: "Esc", email: at("wants.admin"),
      password: strong, confirmPassword: strong, role: "admin" } });
    check("signup cannot self-assign admin role",
      r.status === 201 && r.body?.user?.role === "student", r.body?.user?.role);
  }
}

/* ================= LOGIN ================= */
section("Login");

{
  const c = new Client();
  await c.primeCsrf();

  const bad = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: "WrongPass1!" } });
  check("invalid password rejected with generic message",
    bad.status === 401 && bad.body?.error?.message === "The email or password is incorrect.",
    bad.status + " " + bad.body?.error?.message);

  const missing = await c.fetch("/api/auth/login", { json: { email: at("nobody"), password: strong } });
  check("nonexistent account gives the same generic message",
    missing.status === 401 && missing.body?.error?.message === "The email or password is incorrect.",
    missing.body?.error?.message);

  for (const [label, email] of [["gmail", "john@gmail.com"], ["yahoo", "u@yahoo.com"], ["hotmail", "p@hotmail.com"]]) {
    const r = await c.fetch("/api/auth/login", { json: { email, password: strong } });
    check(`non-VTS ${label} login rejected with access message`,
      r.status === 401 && r.body?.error?.message === "Only VTS email addresses are permitted to access VTS Hub.",
      r.status + " " + r.body?.error?.message);
  }

  const upper = await c.fetch("/api/auth/login", { json: { email: "  " + at("jane.smith").toUpperCase() + " ", password: strong } });
  check("uppercase/whitespace email logs in", upper.status === 200, upper.status + " " + JSON.stringify(upper.body).slice(0,100));
  check("login sets HttpOnly session cookie", c.jar.has("vts_session"));
  check("login response contains no password material",
    !/password|hash|pbkdf2/i.test(JSON.stringify(upper.body)), JSON.stringify(upper.body).slice(0, 150));

  const session = await c.fetch("/api/auth/session");
  check("session persists across requests", session.status === 200 && session.body?.user?.email === at("jane.smith"),
    session.status + " " + session.body?.user?.email);
  check("session exposes only identity fields",
    Object.keys(session.body.user).sort().join(",") ===
      "displayName,email,expiresAt,firstName,id,lastName,provider,role",
    Object.keys(session.body.user).sort().join(","));

  const hub = await c.fetch("/");
  check("authenticated user can load the hub", hub.status === 200 && /VTS Hub/.test(hub.text), hub.status);
  check("hub is served no-store", /no-store/.test(hub.headers.get("cache-control") || ""),
    hub.headers.get("cache-control"));

  const logout = await c.fetch("/api/auth/logout", { json: {} });
  check("logout succeeds", logout.status === 200 && logout.body?.next === "/login", logout.status);
  check("logout clears the session cookie", !c.jar.has("vts_session"));

  const after = await c.fetch("/api/auth/session");
  check("session invalid after logout", after.status === 401, after.status);

  const hubAfter = await c.fetch("/");
  check("hub redirects to /login after logout",
    hubAfter.status === 302 && (hubAfter.headers.get("location") || "").includes("/login"),
    hubAfter.status + " " + hubAfter.headers.get("location"));
}

/* ================= PROTECTED ROUTES ================= */
section("Protected routes");

{
  const anon = new Client();

  const hub = await anon.fetch("/");
  check("protected hub without auth redirects to /login",
    hub.status === 302 && (hub.headers.get("location") || "").includes("/login?next="),
    hub.status + " " + hub.headers.get("location"));

  const doc = await anon.fetch("/files/hr/");
  check("documents without auth are refused", doc.status === 401, doc.status);

  const session = await anon.fetch("/api/auth/session");
  check("session endpoint without auth returns 401", session.status === 401, session.status);

  const login = await anon.fetch("/login");
  check("/login is reachable without auth", login.status === 200 && /Sign in to VTS Hub/.test(login.text), login.status);

  const signup = await anon.fetch("/signup");
  check("/signup is reachable without auth", signup.status === 200, signup.status);
}

/* ================= FORGED SESSIONS ================= */
section("Authentication bypass attempts");

{
  const forged = new Client();
  forged.jar.set("vts_session", "eyJlbWFpbCI6ImhhY2tlckB2dHMuZWR1IiwiZXhwIjo5OTk5OTk5OTk5OTk5fQ.AAAA");
  const r = await forged.fetch("/api/auth/session");
  check("forged session cookie is rejected", r.status === 401, r.status);

  const hub = await forged.fetch("/");
  check("forged cookie cannot open the hub", hub.status === 302, hub.status);

  const doc = await forged.fetch("/files/hr/");
  check("forged cookie cannot open documents", doc.status === 401, doc.status);
}

{
  /* A real payload re-signed with the wrong key, and an expired one. */
  const { signSession } = await import(
    new URL("./netlify/edge-functions/lib/session-token.js", import.meta.url));
  const wrongKey = await signSession(
    { sub: "x", email: "attacker@vts.edu", role: "admin", exp: Date.now() + 3600000 }, "not-the-real-secret");
  const c = new Client();
  c.jar.set("vts_session", wrongKey);
  const r = await c.fetch("/api/auth/session");
  check("session signed with the wrong secret is rejected", r.status === 401, r.status);
}

/* ================= CSRF ================= */
section("CSRF");

{
  const c = new Client();
  await c.primeCsrf();

  const noHeader = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: c.cookieHeader(), origin: BASE },
    body: JSON.stringify({ email: at("jane.smith"), password: strong }),
  });
  check("POST without CSRF header is refused", noHeader.status === 403, noHeader.status);

  const crossOrigin = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: c.cookieHeader(),
               origin: "https://evil.example", "x-vts-csrf": c.jar.get("vts_csrf") },
    body: JSON.stringify({ email: at("jane.smith"), password: strong }),
  });
  check("cross-origin POST is refused", crossOrigin.status === 403, crossOrigin.status);

  const wrongToken = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: c.cookieHeader(), origin: BASE,
               "x-vts-csrf": "not-the-token" },
    body: JSON.stringify({ email: at("jane.smith"), password: strong }),
  });
  check("mismatched CSRF token is refused", wrongToken.status === 403, wrongToken.status);
}

/* ================= OPEN REDIRECT ================= */
section("Open redirect");

{
  const c = new Client();
  await c.primeCsrf();
  for (const evil of ["//evil.example/", "https://evil.example", "/\\evil.example", "/\u0000x"]) {
    const r = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong, next: evil } });
    const next = r.body?.next;
    check("next=" + JSON.stringify(evil) + " is not honoured", r.status === 200 && next === "/", String(next));
  }
  const good = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong, next: "/#worship" } });
  check("same-site next path is honoured", good.body?.next === "/#worship", good.body?.next);
}

/* ================= COOKIE FLAGS ================= */
section("Cookie attributes");

{
  const c = new Client();
  await c.primeCsrf();
  const response = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: c.cookieHeader(), origin: BASE,
               "x-vts-csrf": c.jar.get("vts_csrf") },
    body: JSON.stringify({ email: at("jane.smith"), password: strong }),
  });
  const cookies = response.headers.getSetCookie();
  const session = cookies.find(x => x.startsWith("vts_session="));
  const csrf = cookies.find(x => x.startsWith("vts_csrf="));
  check("session cookie is HttpOnly", /HttpOnly/i.test(session), session);
  check("session cookie is SameSite=Lax", /SameSite=Lax/i.test(session));
  check("session cookie is Path=/", /Path=\//.test(session));
  check("CSRF cookie is readable by script (not HttpOnly)", !/HttpOnly/i.test(csrf), csrf);
  check("session cookie value is not the password", !session.includes(strong));
}

/* ================= SESSION FIXATION ================= */
section("Session fixation");

{
  const c = new Client();
  await c.primeCsrf();
  const first = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong } });
  const cookieA = c.jar.get("vts_session");
  const second = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong } });
  const cookieB = c.jar.get("vts_session");
  check("each sign-in mints a brand-new session cookie", cookieA !== cookieB && Boolean(cookieA) && Boolean(cookieB));

  /* An attacker-chosen session id must not survive sign-in. */
  const planted = new Client();
  await planted.primeCsrf();
  planted.jar.set("vts_session", "attacker-planted-value");
  const r = await planted.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong } });
  check("planted session value is replaced, not adopted",
    r.status === 200 && planted.jar.get("vts_session") !== "attacker-planted-value");
}

/* ================= PASSWORD STORAGE ================= */
section("Password storage");

{
  /* Driven in-process against the real provider and store, because the
     API deliberately never exposes a hash - which is itself the point
     being tested. */
  const LIB = new URL("./netlify/edge-functions/lib/", import.meta.url);
  process.env.VTS_AUTH_STORE = "memory";
  const { developmentAuth } = await import(new URL("providers/development-auth.js", LIB));
  const store = await import(new URL("user-store.js", LIB));

  const created = await developmentAuth.signUp({
    firstName: "Store", lastName: "Check", email: at("store.check"),
    password: strong, confirmPassword: strong, siteOrigin: BASE,
  });
  check("provider creates the account", created.ok === true, JSON.stringify(created).slice(0, 120));
  check("provider return value has no hash", !("passwordHash" in (created.user || {})),
    Object.keys(created.user || {}).join(","));

  const user = await store.findUserByEmail(at("store.check"));
  check("stored record exists", Boolean(user));
  check("record holds no plaintext password", JSON.stringify(user).indexOf(strong) === -1);
  check("password is stored as a PBKDF2 hash", /^pbkdf2-sha256\$210000\$/.test(user.passwordHash),
    String(user.passwordHash).slice(0, 30));
  check("publicUser() strips the hash", !("passwordHash" in store.publicUser(user)),
    Object.keys(store.publicUser(user)).join(","));

  const second = await developmentAuth.signUp({
    firstName: "Same", lastName: "Password", email: at("same.password"),
    password: strong, confirmPassword: strong, siteOrigin: BASE,
  });
  const other = await store.findUserByEmail(at("same.password"));
  check("identical passwords produce different hashes (per-account salt)",
    second.ok && user.passwordHash !== other.passwordHash);

  const unconfirmed = await developmentAuth.signIn({ email: at("store.check"), password: strong });
  check("provider refuses an unconfirmed account even with the right password",
    unconfirmed.ok === false && unconfirmed.code === "EMAIL_UNVERIFIED", unconfirmed.code);
  await store.updateUser(at("store.check"), { emailVerifiedAt: Date.now() });

  const good = await developmentAuth.signIn({ email: at("store.check"), password: strong });
  const bad = await developmentAuth.signIn({ email: at("store.check"), password: strong + "x" });
  check("provider accepts the right password", good.ok === true);
  check("provider rejects the wrong password", bad.ok === false && bad.code === "INVALID_CREDENTIALS");
  check("failed sign-in returns no user object", !("user" in bad));

  /* Timing: a missing account and a wrong password should cost about
     the same, so neither can be told from the other by stopwatch. */
  const t1 = Date.now(); await developmentAuth.signIn({ email: at("store.check"), password: "Wrong1!aa" });
  const wrongPasswordMs = Date.now() - t1;
  const t2 = Date.now(); await developmentAuth.signIn({ email: at("no.such.person"), password: "Wrong1!aa" });
  const noAccountMs = Date.now() - t2;
  const ratio = Math.max(wrongPasswordMs, noAccountMs) / Math.max(1, Math.min(wrongPasswordMs, noAccountMs));
  check("unknown account costs about the same as a wrong password", ratio < 3,
    wrongPasswordMs + "ms vs " + noAccountMs + "ms");
}

section("Passwords are never logged");

{
  const { readFile } = await import("node:fs/promises");
  const logPath = process.env.SERVER_LOG;
  if (!logPath) {
    check("server log available for inspection", false, "SERVER_LOG not set");
  } else {
    const log = await readFile(logPath, "utf8");
    check("password never appears in the server log", !log.includes(strong));
    check("no password hash appears in the server log", !/pbkdf2-sha256\$/.test(log));
    check("session cookie value never appears in the server log", !/vts_session=[A-Za-z0-9]/.test(log));
  }
}

/* ================= RATE LIMITING ================= */
section("Rate limiting");

{
  const c = new Client();
  await c.primeCsrf();
  let sawLimit = false, statuses = [];
  for (let i = 0; i < 12; i++) {
    const r = await c.fetch("/api/auth/login", { json: { email: at("ratelimit"), password: "WrongPass" + i + "!" } });
    statuses.push(r.status);
    if (r.status === 429) { sawLimit = true; break; }
  }
  check("repeated failed logins are rate limited", sawLimit, statuses.join(","));

  const good = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong } });
  check("a different account is unaffected by the lockout", good.status === 200, good.status);
}

/* ================= MICROSOFT BUTTON ================= */
section("Microsoft Entra button");

{
  const c = new Client();
  const ctx = await c.fetch("/api/auth/context");
  check("server reports Microsoft as unavailable", ctx.body?.microsoft?.available === false);
  check("server marks it Coming Soon", ctx.body?.microsoft?.status === "Coming Soon", ctx.body?.microsoft?.status);
  check("server supplies the help text",
    ctx.body?.microsoft?.help === "Microsoft Entra authentication is currently being configured by the VTS development team.",
    ctx.body?.microsoft?.help);
  check("mode is development", ctx.body?.mode === "development", ctx.body?.mode);
  check("context response leaks no secret",
    !/VTS_SESSION_SECRET|pbkdf2|passwordHash/i.test(JSON.stringify(ctx.body)));

  for (const page of ["/login", "/signup"]) {
    const html = (await c.fetch(page)).text;
    check(page + " shows the Microsoft button", /Sign in with Microsoft/.test(html));
    check(page + " renders it disabled in the markup", /id="microsoft-btn"[^>]*\sdisabled/.test(html));
    check(page + " marks it Coming Soon", /Coming Soon/.test(html));
    check(page + " has no click handler or href on it",
      !/id="microsoft-btn"[^>]*(onclick|href)/.test(html));
    check(page + " never references a Microsoft auth endpoint",
      !/login\.microsoftonline\.com/.test(html));
  }
}

/* ================= ENTRA MODE SWAP ================= */
section("Provider swap (AUTH_MODE=entra)");

{
  /* Proves the seam: flipping the mode changes who answers, without
     touching the application. Exercised in-process. */
  const libs = new URL("./netlify/edge-functions/lib/", import.meta.url);
  const before = process.env.AUTH_MODE;
  process.env.AUTH_MODE = "entra";
  const service = await import(new URL("auth-service.js", libs));
  check("AUTH_MODE=entra selects MicrosoftEntraAuth", service.provider().id === "entra", service.provider().id);
  check("Entra provider refuses password sign-in", service.provider().supportsPasswordSignIn === false);
  check("Entra provider refuses password sign-up", service.provider().supportsPasswordSignUp === false);
  check("Entra provider refuses password reset", service.provider().supportsPasswordReset === false);
  check("Entra provider does not do email verification",
    service.provider().describe().emailVerification?.required === false);
  const described = service.provider().describe();
  check("Entra provider is not marked temporary", described.temporary === false);
  process.env.AUTH_MODE = before;
  check("AUTH_MODE back to development selects DevelopmentAuth", service.provider().id === "development");
}

/* ================= ERROR HANDLING ================= */
section("Error handling");

{
  const c = new Client();
  await c.primeCsrf();
  const bad = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: c.cookieHeader(), origin: BASE,
               "x-vts-csrf": c.jar.get("vts_csrf") },
    body: "{not json",
  });
  const body = await bad.text();
  check("malformed body gets a friendly message", bad.status === 400 &&
    body.includes("We couldn't complete your request right now."), bad.status + " " + body.slice(0, 80));
  check("no stack trace is exposed", !/\bat \w+ \(|node_modules|\.mjs:\d+/.test(body));

  const notFound = await c.fetch("/api/auth/nope");
  check("unknown auth route returns 404 without detail", notFound.status === 404, notFound.status);

  const wrongMethod = await c.fetch("/api/auth/login", { method: "GET" });
  check("wrong method returns 405", wrongMethod.status === 405, wrongMethod.status);
}

/* ================= PREVIEW MODE ================= */
section("Existing preview affordance");

{
  const c = new Client();
  const preview = await c.fetch("/?preview");
  check("/?preview still renders the hub (existing feature kept)", preview.status === 200, preview.status);
  const doc = await c.fetch("/files/hr/");
  check("preview grants no access to documents", doc.status === 401, doc.status);
}

/* ================= FORGOT / RESET PASSWORD ================= */
section("Forgot / reset password");

{
  const email = at("reset.me");
  const newPassword = "N3w!Passw0rd";

  /* An account, and a signed-in session that should NOT survive the
     reset. */
  const victim = new Client();
  await victim.primeCsrf();
  const made = await victim.fetch("/api/auth/signup", { json: {
    firstName: "Reset", lastName: "Me", email, password: strong, confirmPassword: strong } });
  check("account for the reset flow is created", made.status === 201, made.status);
  await confirm(victim, email);
  await victim.fetch("/api/auth/login", { json: { email, password: strong } });
  const before = await victim.fetch("/api/auth/session");
  check("pre-reset session is valid", before.status === 200, before.status);

  const c = new Client();
  await c.primeCsrf();

  const gmail = await c.fetch("/api/auth/forgot", { json: { email: "john@gmail.com" } });
  check("forgot refuses a non-VTS address", gmail.status === 400 &&
    gmail.body?.error?.message === "Only VTS email addresses are permitted to access VTS Hub.",
    gmail.status + " " + gmail.body?.error?.message);

  const unknown = await c.fetch("/api/auth/forgot", { json: { email: at("nobody.here") } });
  check("forgot for an unknown address still says ok", unknown.status === 200 && unknown.body?.ok === true,
    unknown.status);

  const outboxBefore = (await c.fetch("/__dev/outbox?json")).body.length;

  const known = await c.fetch("/api/auth/forgot", { json: { email: "  " + email.toUpperCase() + " " } });
  check("forgot for a known address (uppercase, padded) says ok", known.status === 200, known.status);
  check("known and unknown addresses get the identical response",
    JSON.stringify(known.body) === JSON.stringify(unknown.body),
    JSON.stringify(known.body) + " vs " + JSON.stringify(unknown.body));
  check("forgot response contains no token", !/token/i.test(JSON.stringify(known.body)));

  const outbox = (await c.fetch("/__dev/outbox?json")).body;
  check("unknown address sent no mail; known address sent one", outbox.length === outboxBefore + 1,
    outboxBefore + " -> " + outbox.length);

  const mail = outbox[outbox.length - 1];
  check("mail is addressed to the account holder", mail?.to === email, mail?.to);
  const link = (/https?:\/\/\S+/.exec(mail?.text || "") || [])[0] || "";
  let token = "";
  try { token = new URL(link).searchParams.get("token") || ""; } catch {}
  check("mail carries a reset link on this site with a token",
    link.startsWith(BASE + "/reset?token=") && token.length > 30, link.slice(0, 60));

  const bad = await c.fetch("/api/auth/reset", { json: {
    token: "not-a-real-token", password: newPassword, confirmPassword: newPassword } });
  check("reset with a bogus token is refused", bad.status === 400 && bad.body?.error?.code === "RESET_INVALID",
    bad.status + " " + bad.body?.error?.code);

  const weak = await c.fetch("/api/auth/reset", { json: {
    token, password: "weak", confirmPassword: "weak" } });
  check("reset with a weak password is refused", weak.status === 400 && weak.body?.error?.code === "PASSWORD_WEAK",
    weak.body?.error?.code);

  const mismatch = await c.fetch("/api/auth/reset", { json: {
    token, password: newPassword, confirmPassword: newPassword + "x" } });
  check("reset with mismatched passwords is refused",
    mismatch.status === 400 && mismatch.body?.error?.message === "Passwords do not match.",
    mismatch.body?.error?.message);

  const done = await c.fetch("/api/auth/reset", { json: {
    token, password: newPassword, confirmPassword: newPassword } });
  check("reset with a valid token and a good password succeeds (link survived the typos above)",
    done.status === 200 && done.body?.next === "/login?reset=1",
    done.status + " " + JSON.stringify(done.body));
  check("reset does not sign the browser in", !c.jar.has("vts_session"));

  const again = await c.fetch("/api/auth/reset", { json: {
    token, password: newPassword, confirmPassword: newPassword } });
  check("reset link is single-use", again.status === 400 && again.body?.error?.code === "RESET_INVALID",
    again.status);

  const oldPw = await c.fetch("/api/auth/login", { json: { email, password: strong } });
  check("old password no longer works", oldPw.status === 401, oldPw.status);

  const after = await victim.fetch("/api/auth/session");
  check("session that existed before the reset is now invalid", after.status === 401, after.status);
  const hub = await victim.fetch("/");
  check("that session can no longer open the hub", hub.status === 302, hub.status);

  const newPw = await c.fetch("/api/auth/login", { json: { email, password: newPassword } });
  check("new password signs in", newPw.status === 200, newPw.status + " " + JSON.stringify(newPw.body).slice(0, 80));
  const fresh = await c.fetch("/api/auth/session");
  check("session issued after the reset is valid", fresh.status === 200, fresh.status);

  /* Three requests per address per window; the fourth is refused. */
  const limiter = new Client();
  await limiter.primeCsrf();
  const target = at("flood.me");
  let statuses = [];
  for (let i = 0; i < 4; i++) {
    statuses.push((await limiter.fetch("/api/auth/forgot", { json: { email: target } })).status);
  }
  check("repeated reset requests for one address are rate limited",
    statuses.slice(0, 3).every((x) => x === 200) && statuses[3] === 429, statuses.join(","));

  const noCsrf = await fetch(BASE + "/api/auth/forgot", {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email }),
  });
  check("forgot requires the CSRF token", noCsrf.status === 403, noCsrf.status);

  const loginPage = (await c.fetch("/login")).text;
  check("/login offers a Forgot password link", /href="\/forgot"[^>]*>Forgot password\?/.test(loginPage));
  check("/forgot page is reachable", (await c.fetch("/forgot")).status === 200);
  check("/reset page is reachable", (await c.fetch("/reset")).status === 200);
}

/* ================= EMAIL VERIFICATION ================= */
section("Email verification");

{
  const email = at("unconfirmed");
  const c = new Client();
  await c.primeCsrf();
  const made = await c.fetch("/api/auth/signup", { json: {
    firstName: "Un", lastName: "Confirmed", email, password: strong, confirmPassword: strong } });
  check("account is created", made.status === 201, made.status);

  const firstToken = await latestToken(c, email, "/verify");

  /* "Send it again" — same answer for everyone, mail only for the
     unconfirmed account. */
  const unknown = await c.fetch("/api/auth/resend", { json: { email: at("nobody.at.all") } });
  const known = await c.fetch("/api/auth/resend", { json: { email: "  " + email.toUpperCase() } });
  check("resend for unknown and known addresses answer identically",
    unknown.status === 200 && JSON.stringify(unknown.body) === JSON.stringify(known.body),
    unknown.status + " " + JSON.stringify(unknown.body));
  const gmail = await c.fetch("/api/auth/resend", { json: { email: "john@gmail.com" } });
  check("resend refuses a non-VTS address", gmail.status === 400, gmail.status);

  const secondToken = await latestToken(c, email, "/verify");
  check("resend issued a new link", secondToken && secondToken !== firstToken);

  /* A reset token is not a confirmation token, and vice versa. */
  await c.fetch("/api/auth/forgot", { json: { email } });
  const resetToken = await latestToken(c, email, "/reset");
  const crossed = await c.fetch("/api/auth/verify", { json: { token: resetToken } });
  check("a reset link cannot be used to confirm an address",
    crossed.status === 400 && crossed.body?.error?.code === "VERIFY_INVALID", crossed.status);
  const crossedBack = await c.fetch("/api/auth/reset", { json: {
    token: secondToken, password: "Cr0ss!Purpose", confirmPassword: "Cr0ss!Purpose" } });
  check("a confirmation link cannot be used to reset a password",
    crossedBack.status === 400 && crossedBack.body?.error?.code === "RESET_INVALID", crossedBack.status);

  /* The first link still works after a resend (both are valid until
     used or expired), and confirming twice is harmless. */
  const ok = await c.fetch("/api/auth/verify", { json: { token: firstToken } });
  check("an earlier, unused confirmation link still works", ok.status === 200, ok.status);

  const login = await c.fetch("/api/auth/login", { json: { email, password: strong } });
  check("confirmed account signs in", login.status === 200, login.status);
  await c.fetch("/api/auth/logout", { json: {} });

  /* Opening a reset link proves inbox access, so it confirms too. */
  const fresh = at("reset.confirms");
  const d = new Client();
  await d.primeCsrf();
  await d.fetch("/api/auth/signup", { json: {
    firstName: "Via", lastName: "Reset", email: fresh, password: strong, confirmPassword: strong } });
  await d.fetch("/api/auth/forgot", { json: { email: fresh } });
  const viaReset = await latestToken(d, fresh, "/reset");
  const resetOk = await d.fetch("/api/auth/reset", { json: {
    token: viaReset, password: "Re5et!First", confirmPassword: "Re5et!First" } });
  const afterReset = await d.fetch("/api/auth/login", { json: { email: fresh, password: "Re5et!First" } });
  check("an unconfirmed account is confirmed by completing a password reset",
    resetOk.status === 200 && afterReset.status === 200, resetOk.status + " / " + afterReset.status);

  const noCsrf = await fetch(BASE + "/api/auth/verify", {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ token: "x" }),
  });
  check("verify requires the CSRF token", noCsrf.status === 403, noCsrf.status);

  const page = await c.fetch("/verify");
  check("/verify page is reachable and asks for a click, not an automatic submit",
    page.status === 200 && /id="verify-form"/.test(page.text) && !/requestSubmit\(\)/.test(page.text));
  const signupPage = (await c.fetch("/signup")).text;
  check("/signup has the check-your-email state", /id="sent"/.test(signupPage));
  const loginPage = (await c.fetch("/login")).text;
  check("/login has the resend action, hidden by default", /id="resend"[^>]*hidden/.test(loginPage));
}

/* ================= MAIL PROVIDER ADAPTER ================= */
section("Resend adapter (stubbed network)");

{
  /* In-process, with fetch() replaced: proves what would be sent to
     Resend and how a refusal is handled, without a key or a network. */
  const { sendMail, mailDelivery } = await import(
    new URL("./netlify/edge-functions/lib/mailer.js", import.meta.url));

  const realFetch = globalThis.fetch;
  const savedOutbox = globalThis.__vtsDevOutbox;
  globalThis.__vtsDevOutbox = undefined;

  check("with no key configured, delivery is 'log'", mailDelivery() === "log", mailDelivery());

  process.env.RESEND_API_KEY = "re_test_secret_key_do_not_leak";
  process.env.MAIL_FROM = "VTS Hub <hub@vts.edu>";
  check("with key and sender configured, delivery is 'email'", mailDelivery() === "email", mailDelivery());

  let captured = null;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return new Response(JSON.stringify({ id: "msg_1" }), { status: 200 });
  };
  await sendMail({ to: "someone@vts.edu", subject: "Hello", text: "Body text" });
  const body = JSON.parse(captured?.init?.body || "{}");
  check("posts to the Resend API", captured?.url === "https://api.resend.com/emails", captured?.url);
  check("authenticates with the key as a bearer token",
    captured?.init?.headers?.authorization === "Bearer re_test_secret_key_do_not_leak");
  check("sends from MAIL_FROM to the recipient with subject and text",
    body.from === "VTS Hub <hub@vts.edu>" && body.to?.[0] === "someone@vts.edu" &&
    body.subject === "Hello" && body.text === "Body text", JSON.stringify(body));

  const errors = [];
  const realError = console.error;
  console.error = (...args) => errors.push(args.map(String).join(" "));
  globalThis.fetch = async () => new Response('{"message":"invalid from"}', { status: 422 });
  let threw = null;
  try { await sendMail({ to: "someone@vts.edu", subject: "x", text: "y" }); } catch (e) { threw = e; }
  console.error = realError;
  check("a provider refusal throws", Boolean(threw));
  check("the thrown error does not contain the API key", !String(threw).includes("re_test_secret"));
  check("the logged detail does not contain the API key",
    !errors.join("\n").includes("re_test_secret"), errors.join(" | ").slice(0, 120));

  globalThis.fetch = realFetch;
  globalThis.__vtsDevOutbox = savedOutbox;
  delete process.env.RESEND_API_KEY;
  delete process.env.MAIL_FROM;
}

/* ================= SHIPPED ASSETS ================= */
section("Shipped assets");

{
  /* A stray control character inside a regex literal is invisible in a
     diff and silently stops the pattern matching anything. Cheap to
     check, so it is checked. */
  const { readFile, readdir } = await import("node:fs/promises");
  const files = [];
  for (const dir of ["site", "site/assets", "netlify/edge-functions", "netlify/edge-functions/lib",
                     "netlify/edge-functions/lib/providers"]) {
    for (const name of await readdir(new URL("./" + dir + "/", import.meta.url))) {
      if (/[.](js|css|html|toml)$/.test(name)) files.push(dir + "/" + name);
    }
  }
  let dirty = [];
  for (const file of files) {
    const text = await readFile(new URL("./" + file, import.meta.url), "utf8");
    for (const ch of text) {
      const code = ch.codePointAt(0);
      if (code < 32 && code !== 10 && code !== 9 && code !== 13) { dirty.push(file); break; }
    }
  }
  check("no stray control characters in shipped assets", dirty.length === 0, dirty.join(", "));
  check("found assets to scan", files.length > 10, files.length + " files");
}

/* ================= SUMMARY ================= */
console.log("\n" + "=".repeat(52));
console.log("  " + pass + " passed, " + fail + " failed");
if (failures.length) { console.log("\n  Failures:"); failures.forEach(f => console.log("   - " + f)); }
console.log("=".repeat(52));
process.exit(fail ? 1 : 0);
