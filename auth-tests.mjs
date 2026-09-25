/* ------------------------------------------------------------------
   Auth tests
   ------------------------------------------------------------------
   Covers the sign-up rules, the sign-in rules, sessions and logout, and
   the security properties the auth layer is supposed to have. Not
   published — only site/ is.

   Start a FRESH dev server first, then run these against it:

       node dev-server.mjs                     (terminal 1)
       PORT=8888 node auth-tests.mjs           (terminal 2)

   The MariaDB and restart sections run only when VTS_DB_HOST,
   VTS_DB_NAME and VTS_DB_USER (and usually VTS_DB_PASSWORD) are set in
   the environment; otherwise they are reported as SKIP.

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
    /* Every sign-up needs an invitation now. Issued here unless the test
       supplies its own inviteCode — the ones that check the gate do. */
    if (path === "/api/auth/signup" && options.json && !("inviteCode" in options.json)) {
      options = { ...options, json: { ...options.json, inviteCode: await issueInvite(options.json.email) } };
    }
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

/* Sign-up is by invitation (INVITATION_REQUIRED in development-auth.js):
   an administrator issues a code for one named address, because the
   @vts.edu rule can only check the shape of an address, not ownership. */
const LIB_URL = new URL("./netlify/edge-functions/lib/", import.meta.url);
async function issueInvite(email) {
  const store = await import(new URL("user-store.js?invites", LIB_URL));
  const { generateInviteCode, hashInviteCode } = await import(new URL("invite.js", LIB_URL));
  const code = generateInviteCode();
  await store.putInvite(String(email ?? "").trim().toLowerCase(), {
    codeHash: await hashInviteCode(code),
    issuedAt: new Date().toISOString(),
  });
  return code;
}

/* Pulls the newest message for `email` out of the dev outbox and
   returns the token from its link, or "" if there is none. */
async function latestToken(client, email, path) {
  const outbox = (await client.fetch("/__dev/outbox?json")).body;
  const mail = [...outbox].reverse().find((m) => m.to === email && m.text.includes(path + "?token="));
  if (!mail) return "";
  const link = (/https?:\/\/\S+/.exec(mail.text) || [])[0] || "";
  try { return new URL(link).searchParams.get("token") || ""; } catch { return ""; }
}

/* Email verification is disabled for the temporary development auth
   (see EMAIL_VERIFICATION_REQUIRED in providers/development-auth.js), so
   a new account is usable the moment it is created. Kept as a no-op so
   the flows below read in the order a person would follow them. */
async function confirm() {
  return { status: 200 };
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
  check("signup does NOT sign the browser in", !c.jar.has("vts_session"));
  check("signup reports the account is usable at once",
    ok.body?.verification === "not-required" &&
    /created successfully/i.test(ok.body?.message || ""),
    JSON.stringify(ok.body).slice(0, 120));
  check("signup sends the browser to /login?created=1",
    ok.body?.next === "/login?created=1", ok.body?.next);
  check("signup response carries no password field",
    !/password/i.test(JSON.stringify(ok.body)), JSON.stringify(ok.body).slice(0, 120));
  check("signup response carries no token", !/token/i.test(JSON.stringify(ok.body)));
  check("signup default role is student", ok.body?.user?.role === "student", ok.body?.user?.role);

  const noMail = await latestToken(c, at("jane.smith"), "/verify");
  check("NO confirmation mail is sent", noMail === "", noMail.slice(0, 12));

  const immediate = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: strong } });
  check("the new account can sign in immediately", immediate.status === 200,
    immediate.status + " " + (immediate.body?.error?.code || ""));
  check("...and that sign-in issues the normal session cookie", c.jar.has("vts_session"));
  await c.fetch("/api/auth/logout", { json: {} });
  await c.primeCsrf();

  const wrong = await c.fetch("/api/auth/login", { json: { email: at("jane.smith"), password: "Wrong!Pw1" } });
  check("the wrong password is still refused",
    wrong.status === 401 && wrong.body?.error?.code === "INVALID_CREDENTIALS", wrong.body?.error?.code);

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

  /* Written through this instance of the store, which is the one the
     provider reads: the shared helper above talks to a different one. */
  const inviteHere = async (email) => {
    const { generateInviteCode, hashInviteCode } = await import(new URL("invite.js", LIB));
    const code = generateInviteCode();
    await store.putInvite(email, {
      codeHash: await hashInviteCode(code),
      issuedAt: new Date().toISOString(),
    });
    return code;
  };

  const created = await developmentAuth.signUp({
    firstName: "Store", lastName: "Check", email: at("store.check"),
    password: strong, confirmPassword: strong, siteOrigin: BASE,
    inviteCode: await inviteHere(at("store.check")),
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
    inviteCode: await inviteHere(at("same.password")),
  });
  const other = await store.findUserByEmail(at("same.password"));
  check("identical passwords produce different hashes (per-account salt)",
    second.ok && user.passwordHash !== other.passwordHash);

  const record = await store.findUserByEmail(at("store.check"));
  check("the account is marked usable at creation (verification disabled)",
    Boolean(record?.emailVerifiedAt), String(record?.emailVerifiedAt));

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

/* ================= PASSWORD RESET BY RECOVERY CODE ================= */
section("Password reset by recovery code");

{
  /* With no email, ownership is proven by the code issued at sign-up.
     The security question this section answers: can someone who knows
     only an address take over the account? */
  const email = at("code.reset");
  const firstPassword = strong;
  const newPassword = "Rec0very!Pass";

  const c = new Client();
  await c.primeCsrf();
  const made = await c.fetch("/api/auth/signup", { json: {
    firstName: "Code", lastName: "Reset", email,
    password: firstPassword, confirmPassword: firstPassword } });
  check("sign-up succeeds", made.status === 201, made.status);

  const code = made.body?.recoveryCode || "";
  check("sign-up returns a recovery code", /^VTSH(-[A-Z0-9]{4}){4}$/.test(code), code);

  /* It is a credential: it must never be retrievable afterwards. */
  const ctxAfter = await c.fetch("/api/auth/context");
  check("the code is not in the context response", !JSON.stringify(ctxAfter.body).includes(code));
  await c.fetch("/api/auth/login", { json: { email, password: firstPassword } });
  const session = await c.fetch("/api/auth/session");
  check("the code is not in the session response", !JSON.stringify(session.body).includes(code));
  await c.fetch("/api/auth/logout", { json: {} });
  await c.primeCsrf();

  /* Stored as a hash, exactly like a password. Read through the same
     backend the server is using — an unqualified import here would pick
     the in-memory store and quietly find nothing. */
  const LIB = new URL("./netlify/edge-functions/lib/", import.meta.url);
  const dbReady = Boolean(process.env.VTS_DB_HOST && process.env.VTS_DB_NAME && process.env.VTS_DB_USER);
  if (dbReady) process.env.VTS_AUTH_STORE = "mariadb";
  const store = await import(new URL("user-store.js?backend=recovery", LIB));
  const row = await store.findUserByEmail(email);
  check("only a hash of the code is stored",
    /^pbkdf2-sha256\$/.test(row?.recoveryCodeHash || ""), String(row?.recoveryCodeHash).slice(0, 22));
  check("the code itself is nowhere in the record", !JSON.stringify(row).includes(code));
  check("publicUser() never exposes it", !("recoveryCodeHash" in store.publicUser(row)));

  /* THE POINT: knowing the address alone is not enough. */
  const noCode = await c.fetch("/api/auth/reset", { json: {
    email, recoveryCode: "", password: newPassword, confirmPassword: newPassword } });
  check("reset with NO code is refused", noCode.status === 400, noCode.status);
  const wrongCode = await c.fetch("/api/auth/reset", { json: {
    email, recoveryCode: "VTSH-AAAA-BBBB-CCCC-DDDD",
    password: newPassword, confirmPassword: newPassword } });
  check("reset with the WRONG code is refused",
    wrongCode.status === 400 && wrongCode.body?.error?.code === "RESET_INVALID",
    wrongCode.status + " " + wrongCode.body?.error?.code);
  check("the old password still works after a failed attempt",
    (await c.fetch("/api/auth/login", { json: { email, password: firstPassword } })).status === 200);
  await c.fetch("/api/auth/logout", { json: {} });
  await c.primeCsrf();

  /* One account's code must not open another's. */
  const other = at("code.other");
  const o = new Client();
  await o.primeCsrf();
  const otherMade = await o.fetch("/api/auth/signup", { json: {
    firstName: "Other", lastName: "Person", email: other,
    password: strong, confirmPassword: strong } });
  const crossed = await c.fetch("/api/auth/reset", { json: {
    email, recoveryCode: otherMade.body?.recoveryCode,
    password: newPassword, confirmPassword: newPassword } });
  check("another account's code does not work", crossed.status === 400, crossed.status);

  /* A weak new password must not spend the code. */
  const weak = await c.fetch("/api/auth/reset", { json: {
    email, recoveryCode: code, password: "weak", confirmPassword: "weak" } });
  check("a weak new password is refused", weak.status === 400 && weak.body?.error?.code === "PASSWORD_WEAK",
    weak.body?.error?.code);
  const mismatch = await c.fetch("/api/auth/reset", { json: {
    email, recoveryCode: code, password: newPassword, confirmPassword: newPassword + "x" } });
  check("mismatched new passwords are refused",
    mismatch.status === 400 && /do not match/i.test(mismatch.body?.error?.message || ""),
    mismatch.body?.error?.message);

  /* The real thing. The code is accepted in the form a person would
     actually retype it. */
  const done = await c.fetch("/api/auth/reset", { json: {
    email, recoveryCode: code.toLowerCase().replace(/-/g, " "),
    password: newPassword, confirmPassword: newPassword } });
  check("the correct code (retyped loosely) resets the password",
    done.status === 200, done.status + " " + JSON.stringify(done.body?.error || ""));
  check("...and the typo attempts above did NOT spend it", done.status === 200);

  const nextCode = done.body?.recoveryCode || "";
  check("a fresh code replaces the one just used",
    /^VTSH(-[A-Z0-9]{4}){4}$/.test(nextCode) && nextCode !== code, nextCode);

  check("the spent code no longer works",
    (await c.fetch("/api/auth/reset", { json: {
      email, recoveryCode: code, password: strong, confirmPassword: strong } })).status === 400);

  check("the old password no longer works",
    (await c.fetch("/api/auth/login", { json: { email, password: firstPassword } })).status === 401);
  const signedIn = await c.fetch("/api/auth/login", { json: { email, password: newPassword } });
  check("the new password works", signedIn.status === 200, signedIn.status);
  await c.fetch("/api/auth/logout", { json: {} });
  await c.primeCsrf();

  /* Same answer whether or not the address exists, so this cannot be
     used to discover who is registered. */
  const unknown = await c.fetch("/api/auth/reset", { json: {
    email: at("never.registered"), recoveryCode: "VTSH-AAAA-BBBB-CCCC-DDDD",
    password: newPassword, confirmPassword: newPassword } });
  check("an unknown address gives the same answer as a wrong code",
    unknown.status === wrongCode.status &&
    unknown.body?.error?.message === wrongCode.body?.error?.message,
    unknown.body?.error?.message);

  const noVts = await c.fetch("/api/auth/reset", { json: {
    email: "someone@gmail.com", recoveryCode: code,
    password: newPassword, confirmPassword: newPassword } });
  check("a non-VTS address is refused", noVts.status === 400 &&
    noVts.body?.error?.code === "EMAIL_NOT_ALLOWED", noVts.body?.error?.code);

  const noCsrf = await fetch(BASE + "/api/auth/reset", {
    method: "POST", headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email, recoveryCode: nextCode, password: strong, confirmPassword: strong }),
  });
  check("reset requires the CSRF token", noCsrf.status === 403, noCsrf.status);
}

section("Reset: guessing the code is rate limited");

{
  const email = at("guess.target");
  const c = new Client();
  await c.primeCsrf();
  await c.fetch("/api/auth/signup", { json: {
    firstName: "Guess", lastName: "Target", email, password: strong, confirmPassword: strong } });

  let sawLimit = false;
  for (let i = 0; i < 12; i++) {
    const r = await c.fetch("/api/auth/reset", { json: {
      email, recoveryCode: "VTSH-ZZZZ-ZZZZ-ZZZZ-ZZZ" + (i % 10),
      password: "Gu3ssing!Pw", confirmPassword: "Gu3ssing!Pw" } });
    if (r.status === 429) { sawLimit = true; break; }
  }
  check("repeated wrong codes for one address are rate limited", sawLimit);
}

section("Forgot page: a signpost, not a mail form");

{
  const c = new Client();
  const page = await c.fetch("/forgot");
  check("/forgot still loads", page.status === 200, page.status);
  check("...and points at the reset page", /href="\/reset"/.test(page.text));
  check("...with no email form left on it", !/id="forgot-form"/.test(page.text));

  /* The route stays, refusing plainly, so an old client gets an honest
     answer rather than a silent "check your email". */
  await c.primeCsrf();
  const legacy = await c.fetch("/api/auth/forgot", { json: { email: at("anyone") } });
  check("the old forgot route says a code is needed",
    legacy.status === 400 && legacy.body?.error?.code === "RESET_BY_CODE",
    legacy.status + " " + legacy.body?.error?.code);

  const reset = await c.fetch("/reset");
  check("/reset asks for the address and the code",
    /id="email"/.test(reset.text) && /id="recoveryCode"/.test(reset.text));

  const signup = await c.fetch("/signup");
  check("/signup has somewhere to show the code", /id="recovery-code"/.test(signup.text));
}

/* ================= EMAIL VERIFICATION DISABLED ================= */
section("Sign-up while mail cannot get out");

{
  /* With no working mail, sign-up is by invitation and creates a usable
     account at once: there is no confirmation to wait for. This is the
     policy the dev server resolves to, because the sending domain is
     not verified. The other policy is exercised below. */
  const email = at("no.verification");
  const c = new Client();
  await c.primeCsrf();

  const before = (await c.fetch("/__dev/outbox?json")).body.length;
  const made = await c.fetch("/api/auth/signup", { json: {
    firstName: "No", lastName: "Verification", email, password: strong, confirmPassword: strong } });
  check("signup succeeds", made.status === 201, made.status);
  check("nothing was sent", (await c.fetch("/__dev/outbox?json")).body.length === before);
  check("the response names no token or link",
    !/token|http/i.test(JSON.stringify(made.body)), JSON.stringify(made.body).slice(0, 100));

  const login = await c.fetch("/api/auth/login", { json: { email, password: strong } });
  check("the account signs in with no confirmation step", login.status === 200, login.status);
  await c.fetch("/api/auth/logout", { json: {} });

  /* The server tells the pages so they can drop the resend affordance. */
  const context = (await c.fetch("/api/auth/context")).body;
  check("the server reports verification as not required",
    context?.emailVerification?.required === false,
    JSON.stringify(context?.emailVerification));

  const resend = await c.fetch("/api/auth/resend", { json: { email } });
  check("the resend route reports it is not supported",
    resend.status === 400 && resend.body?.error?.code === "VERIFY_NOT_SUPPORTED",
    resend.status + " " + resend.body?.error?.code);

  /* Accounts left unconfirmed under an older build, before anything
     recorded that a confirmation had been asked for, must not be
     stranded: there is no confirmation mail to wait for any more. */
  const LIB = new URL("./netlify/edge-functions/lib/", import.meta.url);
  const store = await import(new URL("user-store.js", LIB));
  const stranded = at("stranded.before");
  const s2 = new Client();
  await s2.primeCsrf();
  await s2.fetch("/api/auth/signup", { json: {
    firstName: "Stran", lastName: "Ded", email: stranded, password: strong, confirmPassword: strong } });
  await store.updateUser(stranded, { emailVerifiedAt: null });
  const strandedLogin = await s2.fetch("/api/auth/login", { json: { email: stranded, password: strong } });
  check("an account left unconfirmed earlier can now sign in",
    strandedLogin.status === 200, strandedLogin.status + " " + (strandedLogin.body?.error?.code || ""));
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

/* ================= PERSISTENCE ================= */
section("Persistence: store selection is explicit and fail-safe");

{
  /* Each rule runs in a fresh process so the module's cached choice
     cannot leak between cases. */
  const { spawn } = await import("node:child_process");
  const ROOT = new URL("./", import.meta.url);
  const probe = `
    import("./netlify/edge-functions/lib/user-store.js")
      .then((s) => s.ensureStore())
      .then((k) => { console.log("OK " + k); process.exit(0); })
      .catch((e) => { console.log("FAIL " + e.message.split("\\n")[0]); process.exit(0); });`;
  async function choose(extra) {
    const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, ...extra };
    return new Promise((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", probe], { cwd: ROOT, env });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.on("close", () => resolve((out.split(/\r?\n/).find((l) => /^(OK|FAIL)/.test(l)) || "").trim()));
    });
  }

  check("development + unset -> memory", (await choose({})) === "OK memory");
  check("development + memory -> memory", (await choose({ VTS_AUTH_STORE: "memory" })) === "OK memory");
  check("production + memory is REFUSED",
    /^FAIL .*refused/.test(await choose({ NODE_ENV: "production", VTS_AUTH_STORE: "memory" })));
  check("production + unset is REFUSED (no silent fallback)",
    /^FAIL .*No account store configured/.test(await choose({ NODE_ENV: "production" })));
  check("unknown store value is an error",
    /^FAIL .*Unknown VTS_AUTH_STORE/.test(await choose({ VTS_AUTH_STORE: "bogus" })));
  check("mariadb with VTS_DB_* missing is an error, not memory",
    /^FAIL .*VTS_DB_NAME/.test(await choose({ VTS_AUTH_STORE: "mariadb" })));
  check("mariadb unreachable is an error, not memory",
    /^FAIL .*ECONNREFUSED/.test(await choose({
      VTS_AUTH_STORE: "mariadb", VTS_DB_HOST: "127.0.0.1", VTS_DB_PORT: "1", VTS_DB_NAME: "x", VTS_DB_USER: "x" })));
}

section("Persistence: MariaDB backend");

const DB = {
  VTS_DB_HOST: process.env.VTS_DB_HOST, VTS_DB_PORT: process.env.VTS_DB_PORT || "3306",
  VTS_DB_NAME: process.env.VTS_DB_NAME, VTS_DB_USER: process.env.VTS_DB_USER,
  VTS_DB_PASSWORD: process.env.VTS_DB_PASSWORD || "",
};
const haveDb = Boolean(DB.VTS_DB_HOST && DB.VTS_DB_NAME && DB.VTS_DB_USER);

if (!haveDb) {
  console.log("  SKIP  set VTS_DB_HOST / VTS_DB_NAME / VTS_DB_USER (and VTS_DB_PASSWORD / VTS_DB_PORT) to run these");
} else {
  /* In-process, against the real database. A query-string suffix gives
     this import its own module instance, so the memory store chosen by
     the earlier in-process section is not reused. */
  const LIB = new URL("./netlify/edge-functions/lib/", import.meta.url);
  Object.assign(process.env, DB, { VTS_AUTH_STORE: "mariadb" });
  const store = await import(new URL("user-store.js?backend=mariadb", LIB));
  const mdb = await import(new URL("store-mariadb.js", LIB));
  const { hashPassword } = await import(new URL("password.js", LIB));
  const { sha256Hex } = await import(new URL("runtime.js", LIB));

  check("ensureStore() reports mariadb", (await store.ensureStore()) === "mariadb");

  const email = at("db.persist");
  const hash = await hashPassword(strong);
  const created = await store.createUser({ email, passwordHash: hash, firstName: "Data", lastName: "Base", role: "student" });
  check("createUser writes a row", created.ok === true);
  const dup = await store.createUser({ email, passwordHash: hash, firstName: "Dup", lastName: "Licate", role: "student" });
  check("duplicate createUser is refused by the primary key", dup.ok === false && dup.reason === "exists");

  const row = await store.findUserByEmail(email);
  check("row round-trips: email, names, role, verified state, timestamps",
    Boolean(row) && row.email === email && row.firstName === "Data" && row.lastName === "Base" &&
    row.role === "student" && row.emailVerifiedAt === null && Boolean(row.createdAt) && Boolean(row.updatedAt));
  check("row holds a PBKDF2 hash, never the password",
    /^pbkdf2-sha256\$/.test(row.passwordHash) && JSON.stringify(row).indexOf(strong) === -1);

  await store.updateUser(email, { emailVerifiedAt: Date.now(), passwordChangedAt: Date.now() });
  const updated = await store.findUserByEmail(email);
  check("updateUser persists verification and password-changed timestamps",
    Boolean(updated.emailVerifiedAt) && Boolean(updated.passwordChangedAt));

  const live = await sha256Hex("live-token-" + RUN);
  await store.putToken(live, { email, purpose: "reset", expiresAt: Date.now() + 60000 });
  check("token cannot be redeemed for another purpose", (await store.takeToken(live, "verify")) === null);
  await store.putToken(live, { email, purpose: "reset", expiresAt: Date.now() + 60000 });
  check("token is redeemed once", (await store.takeToken(live, "reset"))?.email === email);
  check("...and is gone afterwards", (await store.takeToken(live, "reset")) === null);
  const stale = await sha256Hex("stale-token-" + RUN);
  await store.putToken(stale, { email, purpose: "reset", expiresAt: Date.now() - 1 });
  check("expired reset token is refused", (await store.takeToken(stale, "reset")) === null);

  const { createPool } = await import("mysql2/promise");
  const pool = createPool({ host: DB.VTS_DB_HOST, port: Number(DB.VTS_DB_PORT), database: DB.VTS_DB_NAME,
    user: DB.VTS_DB_USER, password: DB.VTS_DB_PASSWORD });
  const [rows] = await pool.query("SELECT kind FROM " + mdb.TABLE + " WHERE JSON_VALUE(v, '$.email') = ?", [email]);
  check("the account is a row in " + mdb.TABLE, rows.length === 1 && rows[0].kind === "user");
  const [plain] = await pool.query("SELECT COUNT(*) AS n FROM " + mdb.TABLE + " WHERE v LIKE ?", ["%" + strong + "%"]);
  check("no row anywhere contains the plaintext password", Number(plain[0].n) === 0);
  await pool.end();
}

section("Persistence: sign in survives a Node restart");

if (!haveDb) {
  console.log("  SKIP  needs the MariaDB variables above");
} else {
  /* Two server processes in turn on a private port, sharing only the
     database and the session secret — what the user reported as Bug 1. */
  const { spawn } = await import("node:child_process");
  const ROOT = new URL("./", import.meta.url);
  const PORT = 8909, B = "http://localhost:" + PORT;
  const SECRET = "test-secret-" + RUN;
  const boot = () => {
    const child = spawn(process.execPath, ["dev-server.mjs"], {
      cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, PORT: String(PORT),
        VTS_SESSION_SECRET: SECRET, VTS_MAIL_OUTBOX: "true", VTS_AUTH_STORE: "mariadb", ...DB },
    });
    let log = ""; child.stdout.on("data", (d) => (log += d)); child.stderr.on("data", (d) => (log += d));
    return { child, log: () => log };
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, tries = 40) => { for (let i = 0; i < tries; i++) { if (fn()) return true; await sleep(250); } return false; };
  const rest = async (path, body, jar) => {
    const headers = { "content-type": "application/json", origin: B };
    if (jar.csrf) { headers["x-vts-csrf"] = jar.csrf; headers.cookie = "vts_csrf=" + jar.csrf; }
    const r = await fetch(B + path, { method: body ? "POST" : "GET", headers, body: body && JSON.stringify(body) });
    for (const c of r.headers.getSetCookie?.() || []) { const m = /^vts_csrf=([^;]+)/.exec(c); if (m) jar.csrf = decodeURIComponent(m[1]); }
    return { status: r.status, body: await r.json().catch(() => null) };
  };

  const email = at("survives.restart"), password = "Survive!Me1";
  let server = boot();
  check("server 1 starts on MariaDB", await until(() => /store    mariadb/.test(server.log())));
  const jar = {};
  await rest("/api/auth/context", null, jar);
  const up = await rest("/api/auth/signup", {
    firstName: "Still", lastName: "Here", email, password, confirmPassword: password,
    inviteCode: await issueInvite(email),
  }, jar);
  check("sign up on server 1", up.status === 201, up.status);
  check("sign in on server 1 (no confirmation step needed)",
    (await rest("/api/auth/login", { email, password }, jar)).status === 200);

  server.child.kill();
  await sleep(600);
  server = boot();
  check("server 2 starts on MariaDB", await until(() => /store    mariadb/.test(server.log())));
  const jar2 = {};
  await rest("/api/auth/context", null, jar2);
  const again = await rest("/api/auth/login", { email, password }, jar2);
  check("SAME email + SAME password sign in after the restart", again.status === 200,
    again.status + " " + JSON.stringify(again.body?.error || "").slice(0, 80));
  check("wrong password is still wrong after the restart",
    (await rest("/api/auth/login", { email, password: "Wrong!Pw9" }, jar2)).status === 401);
  server.child.kill();
}

section("Sessions expire; accounts do not");

{
  /* An expired session is refused, and the account behind it signs in
     again with the same password — the distinction the brief draws. */
  const LIB = new URL("./netlify/edge-functions/lib/", import.meta.url);
  const tok = await import(new URL("session-token.js", LIB));
  const secret = "test-secret-" + RUN;
  const who = { id: "u1", email: at("x"), role: "student" };
  const expired = await tok.signSession({ ...tok.sessionPayload(who, "development"), exp: Date.now() - 1000 }, secret);
  check("an expired session token is refused", (await tok.verifySession(expired, secret)) === null);
  const fresh = await tok.signSession(tok.sessionPayload(who, "development"), secret);
  check("a fresh session token is accepted", (await tok.verifySession(fresh, secret))?.email === at("x"));

  const c = new Client();
  await c.primeCsrf();
  const email = at("expiry.user");
  await c.fetch("/api/auth/signup", { json: { firstName: "Ex", lastName: "Piry", email, password: strong, confirmPassword: strong } });
  await confirm(c, email);
  await c.fetch("/api/auth/login", { json: { email, password: strong } });
  /* The cookie expiring client-side looks, to the server, like this: */
  c.jar.delete("vts_session");
  check("without a session the hub is refused", (await c.fetch("/")).status === 302);
  check("...but the same email + password sign in again",
    (await c.fetch("/api/auth/login", { json: { email, password: strong } })).status === 200);
}

/* ================= SECURITY HEADERS ================= */
section("Security headers");

{
  /* netlify.toml is read by Netlify and nothing else, so on Plesk the
     application must set these itself. */
  const c = new Client();
  const page = await c.fetch("/login");

  const csp = page.headers.get("content-security-policy") || "";
  check("Content-Security-Policy is served", csp.length > 0);
  check("...with no inline-script escape hatch",
    /script-src 'self'/.test(csp) && !/script-src[^;]*unsafe-inline/.test(csp), csp.slice(0, 70));
  check("...allowing the two Microsoft hosts MSAL needs",
    csp.includes("https://login.microsoftonline.com") && csp.includes("https://graph.microsoft.com"));
  check("...and closing base-uri and object-src",
    csp.includes("base-uri 'none'") && csp.includes("object-src 'none'"));

  check("X-Frame-Options is served", (page.headers.get("x-frame-options") || "") === "SAMEORIGIN");
  check("X-Content-Type-Options is served", (page.headers.get("x-content-type-options") || "") === "nosniff");
  check("X-Robots-Tag keeps the private hub out of search engines",
    /noindex/.test(page.headers.get("x-robots-tag") || ""), page.headers.get("x-robots-tag"));

  /* HSTS only over HTTPS; the test server is plain HTTP. */
  check("HSTS is withheld over plain HTTP", !page.headers.has("strict-transport-security"));

  /* Every response, not just HTML. */
  const asset = await c.fetch("/assets/auth-client.js");
  check("assets carry the headers too",
    Boolean(asset.headers.get("content-security-policy")) &&
    (asset.headers.get("x-content-type-options") || "") === "nosniff", asset.status);
  const api = await c.fetch("/api/auth/context");
  check("API responses carry them as well", Boolean(api.headers.get("content-security-policy")));

  /* One CSP, never two â€” duplicates are enforced as the intersection. */
  const raw = await fetch(BASE + "/login");
  const all = [...raw.headers].filter(([k]) => k === "content-security-policy");
  check("exactly one Content-Security-Policy header", all.length === 1, String(all.length));
}

section("Reset tokens stay out of access logs");

{
  /* /reset and /verify arrive with a one-time token in the query string.
     Their stylesheets and scripts are requested before the page strips
     it, and each of those requests carries the full URL in Referer,
     which web servers log. no-referrer on those pages closes that. */
  const c = new Client();
  for (const path of ["/reset", "/verify"]) {
    const page = await c.fetch(path);
    check(path + " sends Referrer-Policy: no-referrer",
      (page.headers.get("referrer-policy") || "") === "no-referrer",
      page.headers.get("referrer-policy"));
  }
  const ordinary = await c.fetch("/login");
  check("ordinary pages keep strict-origin-when-cross-origin",
    (ordinary.headers.get("referrer-policy") || "") === "strict-origin-when-cross-origin",
    ordinary.headers.get("referrer-policy"));

  const { referrerPolicyFor } = await import(
    new URL("./netlify/edge-functions/lib/security-headers.js", import.meta.url));
  check("the .html forms are covered too",
    referrerPolicyFor("/reset.html") === "no-referrer" &&
    referrerPolicyFor("/verify.html") === "no-referrer");
  check("and nothing else is", referrerPolicyFor("/") === "strict-origin-when-cross-origin");
}

/* ================= INVITATION REQUIRED ================= */
section("Sign-up is by invitation");

{
  /* The hole this closes: without a confirmation mail, the @vts.edu
     rule checks the SHAPE of an address, not that the person owns it.
     Anyone could otherwise register dean@vts.edu and be inside. */
  const c = new Client();
  await c.primeCsrf();
  const target = at("impostor.target");
  const signUp = (email, inviteCode) =>
    c.fetch("/api/auth/signup", { json: {
      firstName: "Imp", lastName: "Ostor", email,
      password: strong, confirmPassword: strong, inviteCode } });

  const none = await signUp(target, "");
  check("a plausible @vts.edu address with NO invitation is refused",
    none.status === 400 && none.body?.error?.code === "INVITE_REQUIRED",
    none.status + " " + none.body?.error?.code);

  const missing = await c.fetch("/api/auth/signup", { json: {
    firstName: "Imp", lastName: "Ostor", email: target,
    password: strong, confirmPassword: strong, inviteCode: undefined } });
  check("...and so is one with the field left out entirely",
    missing.status === 400 && missing.body?.error?.code === "INVITE_REQUIRED",
    missing.body?.error?.code);

  const madeUp = await signUp(target, "VTSI-AAAA-BBBB");
  check("a made-up code is refused",
    madeUp.status === 400 && madeUp.body?.error?.code === "INVITE_INVALID",
    madeUp.body?.error?.code);

  /* An invitation is bound to one address, so a leaked code is useless
     for anything else. */
  const invited = at("genuinely.invited");
  const code = await issueInvite(invited);
  const borrowed = await signUp(target, code);
  check("somebody else's real code does not work for this address",
    borrowed.status === 400 && borrowed.body?.error?.code === "INVITE_INVALID",
    borrowed.body?.error?.code);
  check("the two refusals are worded identically (no invitation fishing)",
    madeUp.body?.error?.message === borrowed.body?.error?.message);

  check("no account was created by any of that",
    (await c.fetch("/api/auth/login", { json: { email: target, password: strong } })).status === 401);

  /* The invited person, typing the code as a person would. */
  const accepted = await signUp(invited, code.toLowerCase().replace(/-/g, " "));
  check("the invited address, with its own code, succeeds",
    accepted.status === 201, accepted.status + " " + (accepted.body?.error?.code || ""));
  check("...and still gets a recovery code",
    /^VTSH(-[A-Z0-9]{4}){4}$/.test(accepted.body?.recoveryCode || ""));

  /* One invitation, one account. */
  const reused = await signUp(invited, code);
  check("the invitation cannot open a second account",
    reused.status === 409 && reused.body?.error?.code === "ACCOUNT_EXISTS",
    reused.status + " " + reused.body?.error?.code);

  const other = at("second.attempt");
  const reusedElsewhere = await signUp(other, code);
  check("...nor be reused for a different address",
    reusedElsewhere.status === 400 && reusedElsewhere.body?.error?.code === "INVITE_INVALID",
    reusedElsewhere.body?.error?.code);

  /* Order of checks: a non-VTS address is refused on the domain rule,
     which is the truthful reason, not on the invitation. */
  const gmail = await signUp("someone@gmail.com", await issueInvite("someone@gmail.com"));
  check("a non-VTS address is still refused on the domain rule",
    gmail.status === 400 && gmail.body?.error?.code === "EMAIL_NOT_ALLOWED",
    gmail.body?.error?.code);

  /* Only a hash is stored, as with every other credential here. */
  const store = await import(new URL("user-store.js?invites", LIB_URL));
  const fresh = at("hash.check");
  const freshCode = await issueInvite(fresh);
  const record = await store.findInvite(fresh);
  check("only a hash of the invitation is stored",
    /^pbkdf2-sha256\$/.test(record?.codeHash || ""), String(record?.codeHash).slice(0, 22));
  check("the invitation code itself is not in the record",
    !JSON.stringify(record).includes(freshCode));

  /* The pages and the server agree about whether it is needed. */
  const context = (await c.fetch("/api/auth/context")).body;
  check("the server reports that an invitation is required",
    context?.invitation?.required === true, JSON.stringify(context?.invitation));
  const page = await c.fetch("/signup");
  check("the sign-up form asks for one", /id="inviteCode"/.test(page.text));
}

/* ================= SIGN-UP BY EMAIL CONFIRMATION ================= */
section("Sign-up by email confirmation");

{
  /* The policy the site moves to on its own the day mail can actually
     leave it. The shared dev server is (correctly) still on invitations,
     so this runs in-process with the policy pinned and an outbox
     installed to catch the message. */
  const hadPolicy = "VTS_SIGNUP_POLICY" in process.env;
  const policyBefore = process.env.VTS_SIGNUP_POLICY;
  const outboxBefore = globalThis.__vtsDevOutbox;
  process.env.VTS_SIGNUP_POLICY = "email";
  globalThis.__vtsDevOutbox = [];

  const LIB2 = new URL("./netlify/edge-functions/lib/", import.meta.url);
  const { developmentAuth: auth } = await import(
    new URL("providers/development-auth.js?policy=email", LIB2)
  );
  /* No query string: the same instance the provider itself imports. */
  const store2 = await import(new URL("user-store.js", LIB2));
  const { hashPassword } = await import(new URL("password.js", LIB2));

  const policy = await auth.ready();
  check("VTS_SIGNUP_POLICY=email pins confirmation by email",
    policy.name === "email" && policy.emailVerification === true, policy.name);
  check("...and drops the invitation requirement", policy.invitation === false);
  check("the pages are told both", auth.describe().emailVerification?.required === true &&
    auth.describe().invitation?.required === false);

  const email = at("confirm.me");
  const made = await auth.signUp({
    firstName: "Con", lastName: "Firm", email,
    password: strong, confirmPassword: strong, siteOrigin: BASE,
  });
  check("no invitation is needed", made.ok === true, made.code || "");
  check("the holder is told a link is on its way", made.verification === "sent");
  check("the recovery code is still handed over, once",
    /^VTSH(-[A-Z0-9]{4}){4}$/.test(made.recoveryCode || ""));

  const early = await auth.signIn({ email, password: strong });
  check("the account cannot sign in until the link is opened",
    early.ok === false && early.code === "EMAIL_UNVERIFIED", early.code);

  const message = globalThis.__vtsDevOutbox.find((m) => m.to === email);
  check("a confirmation message was sent to that address", Boolean(message));
  const link = /https?:\/\/\S+/.exec(message?.text || "")?.[0] || "";
  const token = link ? new URL(link).searchParams.get("token") : "";
  check("it carries a link with a token", Boolean(token));

  const confirmed = await auth.verifyEmail({ token });
  check("the link confirms the address", confirmed.ok === true, confirmed.code || "");
  const after = await auth.signIn({ email, password: strong });
  check("and then it signs in", after.ok === true, after.code || "");

  /* A recovery code proves possession of the code. It must not be a
     way of confirming an address nobody has proved they can read. */
  const unproven = at("never.confirmed");
  const pending = await auth.signUp({
    firstName: "Pen", lastName: "Ding", email: unproven,
    password: strong, confirmPassword: strong, siteOrigin: BASE,
  });
  check("a second account is created, unconfirmed", pending.ok === true, pending.code || "");
  const reset = await auth.resetPassword({
    email: unproven, recoveryCode: pending.recoveryCode,
    password: "An0ther!Pass2", confirmPassword: "An0ther!Pass2",
  });
  check("its recovery code still resets the password", reset.ok === true, reset.code || "");
  const stillOut = await auth.signIn({ email: unproven, password: "An0ther!Pass2" });
  check("but the reset does NOT confirm the address",
    stillOut.ok === false && stillOut.code === "EMAIL_UNVERIFIED", stillOut.code);

  /* Changing the policy must not lock out the people already using the
     hub. An account made before anything asked for a confirmation is
     not one that owes a confirmation. */
  const legacy = at("predates.confirmation");
  await store2.createUser({
    email: legacy, passwordHash: await hashPassword(strong),
    firstName: "Pre", lastName: "Dates", role: "student", emailVerifiedAt: null,
  });
  const legacyIn = await auth.signIn({ email: legacy, password: strong });
  check("an account predating confirmation is not locked out by it",
    legacyIn.ok === true, legacyIn.code || "");

  /* An unknown value is not obeyed, and does not open sign-up either. */
  process.env.VTS_SIGNUP_POLICY = "off";
  const { signupPolicy: bogus } = await import(
    new URL("providers/development-auth.js?policy=bogus", LIB2)
  );
  const fallback = await bogus();
  check("an unrecognised VTS_SIGNUP_POLICY falls back, never to 'no proof'",
    fallback.emailVerification === true || fallback.invitation === true, fallback.name);

  globalThis.__vtsDevOutbox = outboxBefore;
  if (hadPolicy) process.env.VTS_SIGNUP_POLICY = policyBefore;
  else delete process.env.VTS_SIGNUP_POLICY;
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
