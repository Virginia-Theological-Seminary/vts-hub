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

   Netlify Blobs is not available off-platform, so accounts created here
   live in memory and disappear when the process stops. That is stated
   on startup rather than left to be discovered.
   ------------------------------------------------------------------ */

import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

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
    /* A throwaway secret so sign-in works out of the box. Regenerated
       every start, which means restarting the server invalidates every
       session — correct for a dev server, and never a value that could
       reach production. */
    process.env.VTS_SESSION_SECRET = crypto.randomBytes(48).toString("base64");
    console.log("  env      VTS_SESSION_SECRET generated for this run");
  }
  process.env.AUTH_MODE = process.env.AUTH_MODE || "development";
  process.env.VTS_AUTH_STORE = process.env.VTS_AUTH_STORE || "memory";
}

/* protect-files.js and session.js read Netlify.env directly, as they
   were written to. Shimming it keeps those two files untouched. */
globalThis.Netlify = { env: { get: (key) => process.env[key] } };

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
  /* The two redirects declared in netlify.toml. */
  if (pathname === "/login") pathname = "/login.html";
  if (pathname === "/signup") pathname = "/signup.html";
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

async function send(response, res) {
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

const port = Number(process.env.PORT || 8888);

const server = http.createServer(async (req, res) => {
  const origin = "http://" + (req.headers.host || "localhost:" + port);
  const url = new URL(req.url, origin);

  try {
    const request = await toRequest(req, origin);
    const ip = req.socket.remoteAddress || "127.0.0.1";
    const response = await route(request, url, ip);
    console.log("  " + req.method.padEnd(5), response.status, url.pathname);
    await send(response, res);
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
  console.log("  auth     AUTH_MODE=" + process.env.AUTH_MODE + " (temporary development authentication)");
  console.log("  store    in memory — accounts are lost when this process stops");
  console.log("");
});
