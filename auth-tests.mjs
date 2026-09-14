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
  check("signup returns a session cookie", c.jar.has("vts_session"));
  check("signup response carries no password field",
    !/password/i.test(JSON.stringify(ok.body)), JSON.stringify(ok.body).slice(0, 120));
  check("signup default role is student", ok.body?.user?.role === "student", ok.body?.user?.role);

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
    password: strong, confirmPassword: strong,
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
    password: strong, confirmPassword: strong,
  });
  const other = await store.findUserByEmail(at("same.password"));
  check("identical passwords produce different hashes (per-account salt)",
    second.ok && user.passwordHash !== other.passwordHash);

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
