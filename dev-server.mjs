/* ------------------------------------------------------------------
   Local development server
   ------------------------------------------------------------------
   Not published and not deployed — only site/ is. This exists so the
   temporary development authentication can be run and tested on a
   laptop without the Netlify CLI, which is otherwise the only way to
   execute an edge function locally.

       node dev-server.mjs
       -> http://localhost:8888

   It serves site/ as static files and hands the same three edge
   functions the same Request objects Netlify would, so what is tested
   here is the deployed code path rather than a stand-in for it.

   Accounts: VTS_AUTH_STORE decides (see lib/user-store.js). Unset on
   a laptop means memory, stated on startup. With NODE_ENV=production
   this file refuses to start unless the store is persistent, the
   session secret is set, and the dev outbox is off — a misconfigured
   server that stops is better than one that quietly loses accounts or
   publishes reset links (Bugs 1 and 2 of September 2026).
   ------------------------------------------------------------------ */

import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { applySecurityHeaders } from "./netlify/edge-functions/lib/security-headers.js";

const root = path.dirname(fileURLToPath(import.meta.url));
const siteDir = path.join(root, "site");

/* ---------------- environment ---------------- */

/* .env if it exists, otherwise defaults. Same names as .env.example. */
async function loadEnv() {
  try {
    const raw = await readFile(path.join(root, ".env"), "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (!match) continue;
      const value = match[2].trim().replace(/^["']|["']$/g, "");
      if (!(match[1] in process.env)) process.env[match[1]] = value;
    }
    console.log("  env      .env loaded");
  } catch {
    console.log("  env      no .env file — using development defaults");
  }

  if (!process.env.VTS_SESSION_SECRET) {
    if (isProduction()) {
      fatal("VTS_SESSION_SECRET is not set. Refusing to generate a throwaway secret in " +
            "production: every restart would sign everyone out. Set it in the environment.");
    }
    /* A throwaway secret so sign-in works out of the box on a laptop.
       Regenerated every start, which means restarting invalidates every
       session — correct for a dev server. */
    process.env.VTS_SESSION_SECRET = crypto.randomBytes(48).toString("base64");
    console.log("  env      VTS_SESSION_SECRET generated for this run");
  }
  process.env.AUTH_MODE = process.env.AUTH_MODE || "development";
  /* VTS_AUTH_STORE is deliberately NOT defaulted here. The store module
     decides, and in production it refuses to guess. */
}

function isProduction() {
  return String(process.env.NODE_ENV || "").toLowerCase() === "production";
}

/* A configuration that cannot be served correctly stops the process
   with one clear line. Passenger shows this in the app's log. */
function fatal(message) {
  console.error("");
  console.error("  FATAL  " + message);
  console.error("");
  process.exit(1);
}

/* protect-files.js and session.js read Netlify.env directly, as they
   were written to. Shimming it keeps those two files untouched. */
globalThis.Netlify = { env: { get: (key) => process.env[key] } };

/* ---------------- the dev outbox ---------------- */

/* lib/mailer.js delivers into this array when it is present — the way
   Mailpit or MailHog would catch outgoing mail on a developer's machine.
   /__dev/outbox shows it. Only this file installs the array, and this
   file is never deployed, so the page cannot exist on a real site.

   Installed after .env is read (see the start section), and skipped
   when VTS_MAIL_OUTBOX=false — which lets a Resend key in .env send
   real mail from the laptop, to check the provider before deploying. */

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
  );

/* Turns a bare URL in message text into a link, escaping everything
   else. Message text is built from user-supplied names, so it is
   treated as untrusted even here. */
function linkify(text) {
  return esc(text).replace(/https?:\/\/[^\s<]+/g, (url) => `<a href="${url}">${url}</a>`);
}

function outboxPage(url) {
  const messages = globalThis.__vtsDevOutbox || [];
  const off = !Array.isArray(globalThis.__vtsDevOutbox);

  if (url.searchParams.has("json")) {
    return new Response(JSON.stringify(messages), {
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }

  const items = off
    ? `<p class="empty">The outbox is off (VTS_MAIL_OUTBOX=false) — mail is going out for real.</p>`
    : messages.length
    ? [...messages].reverse().map((m) => `
        <article>
          <header><strong>${esc(m.subject)}</strong><span>to ${esc(m.to)} · ${esc(m.sentAt)}</span></header>
          <pre>${linkify(m.text)}</pre>
        </article>`).join("")
    : `<p class="empty">Nothing yet. Use <a href="/forgot">Forgot password?</a> on the sign-in page.</p>`;

  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
     <title>Dev outbox — VTS Hub</title>
     <style>
       body{font:15px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif;max-width:44rem;margin:5vh auto;padding:0 1.5rem;color:#1b1d21;background:#f6f7f9}
       h1{font-size:20px;color:#293891;margin:0 0 4px} .sub{color:#6b7280;font-size:13.5px;margin:0 0 22px}
       article{background:#fff;border:1px solid #e2e5ea;border-radius:10px;padding:14px 16px;margin-bottom:14px}
       header{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font-size:13.5px;margin-bottom:8px}
       header span{color:#6b7280} pre{white-space:pre-wrap;word-break:break-word;margin:0;font:13.5px/1.5 ui-monospace,Menlo,Consolas,monospace}
       a{color:#293891} .empty{color:#6b7280}
     </style>
     <h1>Dev outbox</h1>
     <p class="sub">Mail the site tried to send this run. Local only — this page does not exist on a deployed site.</p>
     ${items}`,
    { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
  );
}

/* ---------------- static files ---------------- */

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".pdf": "application/pdf",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".txt": "text/plain; charset=utf-8",
};

/* Resolve inside site/ and verify the result is still inside it, so a
   "../" in the URL cannot walk out to _source/ or the repository root. */
function resolveInSite(pathname) {
  const decoded = decodeURIComponent(pathname);
  const resolved = path.resolve(siteDir, "." + path.posix.normalize(decoded));
  return resolved.startsWith(siteDir) ? resolved : null;
}

async function serveStatic(pathname) {
  /* The redirects declared in netlify.toml. */
  if (pathname === "/login") pathname = "/login.html";
  if (pathname === "/signup") pathname = "/signup.html";
  if (pathname === "/forgot") pathname = "/forgot.html";
  if (pathname === "/reset") pathname = "/reset.html";
  if (pathname === "/verify") pathname = "/verify.html";
  if (pathname === "/" || pathname.endsWith("/")) pathname += "index.html";

  const file = resolveInSite(pathname);
  if (!file) return new Response("Not found", { status: 404 });

  try {
    const info = await stat(file);
    if (!info.isFile()) return new Response("Not found", { status: 404 });
  } catch {
    return new Response("Not found", { status: 404 });
  }

  const body = await readFile(file);
  const headers = {
    "content-type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream",
    "x-content-type-options": "nosniff",
  };
  if (/\.html$/.test(file)) headers["cache-control"] = "no-store, must-revalidate";
  return new Response(body, { status: 200, headers });
}

/* ---------------- edge functions ---------------- */

const load = (rel) => import(pathToFileURL(path.join(root, rel)).href);

const [authApi, protectApp, protectFiles, sessionApi] = [
  "netlify/edge-functions/auth-api.js",
  "netlify/edge-functions/protect-app.js",
  "netlify/edge-functions/protect-files.js",
  "netlify/edge-functions/session.js",
];

async function route(request, url, ip) {
  const context = { ip, next: () => serveStatic(url.pathname) };

  /* The outbox route exists only while the outbox does. */
  if (url.pathname === "/__dev/outbox" && outboxOn) {
    return outboxPage(url);
  }
  if (url.pathname.startsWith("/api/auth")) {
    return (await load(authApi)).default(request, context);
  }
  if (url.pathname === "/api/session") {
    return (await load(sessionApi)).default(request, context);
  }
  if (url.pathname.startsWith("/files/")) {
    return (await load(protectFiles)).default(request, context);
  }
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return (await load(protectApp)).default(request, context);
  }
  return serveStatic(url.pathname);
}

/* ---------------- bridge ---------------- */

function toRequest(req, origin) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("error", reject);
    req.on("end", () => {
      const hasBody = req.method !== "GET" && req.method !== "HEAD";
      resolve(
        new Request(new URL(req.url, origin), {
          method: req.method,
          headers: req.headers,
          body: hasBody ? Buffer.concat(chunks) : undefined,
        })
      );
    });
  });
}

async function send(response, res, { pathname = "/", secure = true } = {}) {
  /* Reassigned, not just mutated: a redirect's headers are immutable,
     so applySecurityHeaders hands back a rebuilt response for those. */
  response = applySecurityHeaders(response, { pathname, secure });

  const headers = {};
  response.headers.forEach((value, key) => {
    if (key !== "set-cookie") headers[key] = value;
  });

  /* Multiple Set-Cookie headers have to stay separate — the auth
     endpoints set the session and CSRF cookies in one response. */
  const cookies = response.headers.getSetCookie?.() || [];
  if (cookies.length) headers["set-cookie"] = cookies;

  res.writeHead(response.status, headers);
  if (response.body) {
    res.end(Buffer.from(await response.arrayBuffer()));
  } else {
    res.end();
  }
}

/* ---------------- start ---------------- */

await loadEnv();

const outboxOn = String(process.env.VTS_MAIL_OUTBOX || "true").toLowerCase() !== "false";
if (outboxOn && isProduction()) {
  fatal("The dev mail outbox cannot run in production: it would publish every password-reset " +
        "and confirmation link at /__dev/outbox. Set VTS_MAIL_OUTBOX=false.");
}
if (outboxOn) globalThis.__vtsDevOutbox = [];

/* Prove the account store before taking a single request. */
const { ensureStore } = await load("netlify/edge-functions/lib/user-store.js");
let storeKind;
try {
  storeKind = await ensureStore();
} catch (err) {
  fatal("Account store unavailable — " + (err && err.message ? err.message : String(err)));
}

/* Say, at startup, whether mail can actually leave this server. */
const { mailPreflight } = await load("netlify/edge-functions/lib/mailer.js");
const mailNotes = await mailPreflight();

const port = Number(process.env.PORT || 8888);

const server = http.createServer(async (req, res) => {
  const origin = "http://" + (req.headers.host || "localhost:" + port);
  const url = new URL(req.url, origin);

  try {
    const request = await toRequest(req, origin);
    const ip = req.socket.remoteAddress || "127.0.0.1";
    const response = await route(request, url, ip);
    console.log("  " + req.method.padEnd(5), response.status, url.pathname);
    /* Behind Plesk's nginx and Apache the connection to Node is plain
       HTTP; X-Forwarded-Proto carries what the browser actually used. */
    const secure =
      req.headers["x-forwarded-proto"] === "https" || Boolean(req.socket.encrypted);
    await send(response, res, { pathname: url.pathname, secure });
  } catch (err) {
    console.error("  " + req.method.padEnd(5), 500, url.pathname, err);
    res.writeHead(500, { "content-type": "text/plain" });
    res.end("Internal error");
  }
});

server.listen(port, () => {
  console.log("");
  console.log("  VTS Hub — local development server");
  console.log("  http://localhost:" + port);
  console.log("");
  console.log("  mode     " + (isProduction() ? "production" : "development"));
  console.log("  auth     AUTH_MODE=" + process.env.AUTH_MODE + " (temporary development authentication)");
  console.log("  store    " + storeKind + (storeKind === "memory" ? " — accounts are lost when this process stops" : " — accounts persist"));
  if (outboxOn) {
    console.log("  mail     captured — read it at http://localhost:" + port + "/__dev/outbox");
  } else if (process.env.RESEND_API_KEY && process.env.MAIL_FROM) {
    console.log("  mail     sending for real through Resend, from " + process.env.MAIL_FROM);
  } else {
    console.log("  mail     outbox off but Resend not configured — links will print here");
  }
  for (const note of mailNotes) console.log("  mail     " + note);
  console.log("");
});
