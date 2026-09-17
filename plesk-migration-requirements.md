# VTS Hub — Requirements for migrating from Netlify to Plesk

**Status:** draft for review · **Applies to:** the `Website` project as described in `setup-init.md`
**Target:** a Plesk-managed Linux server. nginx sits in front of Apache; Apache serves `site/` as
the document root at `/`. `.htaccess`, Node.js, PHP and MariaDB are available.

---

## 1. Purpose and scope

The hub currently relies on three things Netlify provides: static hosting of `site/`, edge
functions on four paths, and Netlify Blobs for the temporary development accounts. On Plesk
those become: Apache serving `site/` behind nginx, a long-running Node.js process running the
same edge-function code for the four protected paths, and a MariaDB table for the accounts.

Everything the security model depends on today must hold after the move:

- `/`, `/index.html` and every file under `/files/` are **never** served without a valid session.
- The auth pages, hub and API return the same headers, cookies and status codes as on Netlify.
- No secret is stored in the repository or under the document root.
- `AUTH_MODE=entra` remains a one-variable switch.

Out of scope: the Entra registration itself, content changes, and the SharePoint alternative.
PHP is on the server but is not used by this application (see §7.6).

---

## 2. What Netlify does today, and what replaces it

| Netlify feature | Used by | Replacement on Plesk |
|---|---|---|
| Static publish of `site/` | whole site | Apache document root = `site/`; nginx in front as Plesk's reverse proxy |
| Edge functions (Deno) on `/api/auth/*`, `/api/session`, `/`, `/index.html`, `/files/*` | auth layer | Node.js 20+ LTS daemon on `127.0.0.1:3000`; `.htaccess` in `site/` proxies exactly those paths to it |
| `context.next()` | `protect-app.js`, `protect-files.js` | the Node server's own static handler, as `dev-server.mjs` already does |
| `context.ip` / `x-nf-client-connection-ip` | `rate-limit.js` | first hop of `X-Forwarded-For` as set by nginx and passed on by Apache |
| `Netlify.env.get()` | `protect-files.js`, `session.js` | `process.env` via the existing `globalThis.Netlify` shim, or switch both files to `env()` from `lib/runtime.js` |
| Netlify Blobs | `lib/user-store.js` | MariaDB table `dev_users` (§5.2); only needed while `AUTH_MODE=development` |
| Protected documents in `site/files/` | `protect-files.js` | documents move to `httpdocs/protected/files/`, **outside** the document root; Node serves them after the session check |
| `netlify.toml` headers (CSP, X-Frame-Options, Cache-Control…) | all responses | `.htaccess` `Header` directives for what Apache serves; Node sets them on what it serves |
| `netlify.toml` redirects `/login`, `/signup` | auth pages | `.htaccess` rewrite rules |
| Environment variables UI | secrets | Plesk Node.js panel *Custom environment variables*, or the systemd unit's `EnvironmentFile` |
| Automatic HTTPS | TLS | Plesk Let's Encrypt extension, HTTP→HTTPS redirect, HSTS |
| Deploy previews | testing | a staging subdomain on the same server (e.g. `hub-staging.vts.edu`) |

---

## 3. Target architecture

```
Browser
   |  https://hub.vts.edu
   v
nginx (Plesk reverse proxy, :443)   TLS, HTTP->HTTPS, passes X-Forwarded-*
   |   "Serve static files directly by nginx" = OFF for this domain (§6.1)
   v
Apache (:7081)  DocumentRoot = /var/www/vhosts/hub.vts.edu/httpdocs/site
   |
   |  site/.htaccess
   +-- /assets/*, /vendor/*, /favicon.png            served by Apache from site/
   +-- /login, /signup  -> login.html, signup.html   served by Apache from site/
   +-- /, /index.html, /files/*, /api/*              RewriteRule [P] -> Node
   |
   v
Node.js  server.mjs  (127.0.0.1:3000, systemd or Plesk Node.js app)
   +-- /api/auth/*      auth-api.js
   +-- /api/session     session.js
   +-- /  /index.html   protect-app.js   -> site/index.html
   +-- /files/*         protect-files.js -> httpdocs/protected/files/...   (NOT in site/)
   |
   +-- MariaDB  vtshub.dev_users   (dev accounts)
```

**The two rules that make this safe:**

1. The documents do not live under the document root. Even if every rewrite rule is lost,
   there is no file for Apache or nginx to serve at `/files/…`.
2. nginx must not serve static files directly for this domain, because nginx does not read
   `.htaccess` and would answer `/index.html` and `/files/…` itself.

---

## 4. Server requirements

| Item | Requirement |
|---|---|
| Plesk | Obsidian 18.0.5x or later, Linux |
| Web stack | nginx as reverse proxy in front of Apache. Apache modules: `mod_rewrite`, `mod_proxy`, `mod_proxy_http`, `mod_headers`, `mod_ssl`. `AllowOverride` must include `FileInfo` and `Options` for `site/` (needed for `RewriteRule [P]` and `Header`) |
| Node.js | 20 LTS minimum, 22 LTS preferred. Runs as a persistent daemon, either through the Plesk Node.js extension or a systemd unit (§7.4) |
| MariaDB | 10.6+; one database `vtshub`, one user with rights on that database only; reachable on `localhost` |
| Domain | `hub.vts.edu` (plus `hub-staging.vts.edu`), DNS A/AAAA records pointed at the Plesk server before cutover |
| TLS | Let's Encrypt certificate with auto-renewal; TLS 1.2+ only; HTTP→HTTPS permanent redirect |
| Filesystem layout | `/var/www/vhosts/hub.vts.edu/httpdocs/` = repository root. `httpdocs/site/` = Apache document root. `httpdocs/protected/files/` = the documents (moved from `site/files/`). `httpdocs/netlify/`, `httpdocs/server.mjs` and `httpdocs/_source/` (if deployed at all) are outside the document root |
| Document root setting | Plesk defaults a domain's document root to `httpdocs`. In *Hosting Settings → Document root* it **must** be set to `httpdocs/site`. Left at the default, Apache serves the repository root, including `netlify/`, `protected/`, `server.mjs` and `.env`. The §9 checklist tests for this |
| Permissions | Files owned by the Plesk system user; `site/` world-readable; `protected/` readable by the Node user only |
| Outbound network | Node must reach `https://login.microsoftonline.com` and `https://graph.microsoft.com` for `AUTH_MODE=entra` token verification |
| Time sync | NTP/chrony running. Session expiry and Entra token validation are time-based |

---

## 5. Application changes required (code)

None of these alters the security behaviour; they swap the hosting seams.

1. **Production server entry: `server.mjs`.**
   Derive from `dev-server.mjs` and keep it in the repository root. Differences from the dev server:
   - Listen on `127.0.0.1` and `process.env.PORT` (default 3000). Do not generate a throwaway
     `VTS_SESSION_SECRET`; **refuse to start** if it is missing.
   - Build `request.url` from `X-Forwarded-Proto` and `X-Forwarded-Host`. Apache's
     `mod_proxy` rewrites `Host` to `127.0.0.1:3000` on a `[P]` rewrite and puts the original
     in `X-Forwarded-Host`. The CSRF check in `lib/auth-service.js` compares the `Origin`
     header's host with `request.url`'s host, and `isSecureRequest()` reads
     `X-Forwarded-Proto` for the `Secure` cookie flag. Get either wrong and every login POST
     fails or cookies silently lose `Secure`.
   - Trust `X-Forwarded-*` only when the TCP peer is `127.0.0.1`.
   - Serve `/files/*` from `httpdocs/protected/files/`, not `site/files/`. Keep the
     `resolveInSite`-style containment check against the new base directory.
   - Keep the `globalThis.Netlify = { env: { get } }` shim, or replace the two direct
     `Netlify.env.get()` calls in `protect-files.js` and `session.js` with `env()`.
   - Apply the `netlify.toml` header set (CSP, `X-Frame-Options`, `X-Content-Type-Options`,
     `Referrer-Policy`, `X-Robots-Tag`) to every response Node produces. Apache must **not**
     add them again on proxied responses (§7.3) or browsers see two CSP headers.
   - Log one line per request (method, status, path; no cookies, no bodies) to stdout.

2. **MariaDB user store.** Add a backend to `lib/user-store.js`, selected by
   `VTS_AUTH_STORE=mariadb`:
   - Driver: `mysql2` (the one npm dependency this adds; pinned, installed from
     `httpdocs/package.json`, `node_modules/` outside the document root).
   - Schema:
     ```sql
     CREATE TABLE dev_users (
       user_key     CHAR(40)     NOT NULL PRIMARY KEY,   -- sha256("user:"+email)[0:40], as today
       id           VARCHAR(32)  NOT NULL UNIQUE,
       email        VARCHAR(255) NOT NULL UNIQUE,
       password_hash VARCHAR(512) NOT NULL,
       first_name   VARCHAR(100) NOT NULL DEFAULT '',
       last_name    VARCHAR(100) NOT NULL DEFAULT '',
       role         VARCHAR(32)  NOT NULL,
       created_at   DATETIME(3)  NOT NULL,
       updated_at   DATETIME(3)  NOT NULL
     ) CHARACTER SET utf8mb4;
     ```
   - All queries parameterised; the `get/set/delete/count` interface is unchanged, so
     `createUser`, `updateUser` and the tests do not change. `createUser`'s "exists" check
     becomes an `INSERT` that catches the duplicate-key error.
   - Connection details from `VTS_DB_*` variables (§8). On connection failure the store
     falls back to memory **and logs the existing warning**, exactly as with Blobs today.
   - The table is dropped when `AUTH_MODE=entra` goes live.
   - *Alternative if IT would rather not add a dependency:* a JSON file at `httpdocs/data/users.json`
     written atomically. Adequate for dozens of users; single Node process only.

3. **Client IP.** In `lib/rate-limit.js`, use the first hop of `X-Forwarded-For` (nginx sets
   it from the real client; Apache appends `127.0.0.1`'s view when proxying). Remove the
   Netlify header. A single long-lived process makes the in-memory limiter effective across
   requests.

4. **Documents move.** `git mv site/files protected/files`. `data.js` hrefs stay `/files/...`;
   only the filesystem location changes.

5. **Repository hygiene.** Add `node_modules/`, `data/` to `.gitignore`. Keep the `netlify/`
   folder name for now (the server imports from it; renaming is cosmetic). Delete
   `netlify.toml` once `.htaccess` carries its headers. Update `setup-init.md` steps 2–3 for Plesk.

6. **Tests.** `auth-tests.mjs` accepts `VTS_TEST_BASE_URL` so the same 98 checks run against
   staging. Add: `Secure` flag present over HTTPS, `Origin` mismatch rejected, and
   `GET /files/<doc>.pdf` without a cookie returns 401 **through nginx and Apache**.

---

## 6. nginx requirements (front)

nginx is Plesk's reverse proxy and does not read `.htaccess`. Its job here is TLS and
pass-through; everything routing-related lives in Apache.

1. **Disable "Serve static files directly by nginx"** in *Apache & nginx Settings* for this
   domain. With it on, nginx answers requests for `.html`, `.pdf`, `.js` and so on straight
   from the document root, bypassing the `.htaccess` proxy rules. That would expose
   `index.html` unauthenticated and, if the documents were ever still in `site/files/`, the
   documents too. Also leave "Smart static files processing" off.
   *Accepted cost:* assets pass through Apache. At this site's size that is negligible.

2. **Proxy headers.** Plesk's generated config already sends `Host`, `X-Forwarded-For`,
   `X-Forwarded-Proto` and `X-Real-IP` to Apache. Verify in
   `/var/www/vhosts/system/hub.vts.edu/conf/nginx.conf`; do not override.

3. **Additional nginx directives** (location-level only; Plesk owns the `server {}` block):
   ```nginx
   server_tokens off;
   client_max_body_size 64k;          # auth JSON bodies only; documents are downloads, not uploads
   location ~ /\.(?!well-known) { deny all; }
   ```
   Optional backstop against brute force at the edge (zone declared in an `http`-level
   include, e.g. `/etc/nginx/conf.d/vtshub.conf`):
   ```nginx
   # conf.d/vtshub.conf
   limit_req_zone $binary_remote_addr zone=vtsauth:1m rate=10r/s;
   # domain additional directives
   location ^~ /api/auth/ { limit_req zone=vtsauth burst=20 nodelay; proxy_pass https://127.0.0.1:7081; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Real-IP $remote_addr; }
   ```

4. **HTTP→HTTPS** via Plesk's "Permanent SEO-safe 301 redirect from HTTP to HTTPS". HSTS is
   added by Apache (§7.3) so it appears once.

---

## 7. Apache requirements (document root `site/`)

Apache does the routing. Most of it sits in `site/.htaccess`, which is deployed with the
site. Two directives cannot live in `.htaccess` and go in Plesk → *Apache & nginx Settings*
→ *Additional directives for HTTPS*.

1. **Vhost-level directives (Plesk panel):**
   ```apache
   ProxyPreserveHost Off              # default; Node reads X-Forwarded-Host instead (§5.1)
   ProxyTimeout 30
   <Directory "/var/www/vhosts/hub.vts.edu/httpdocs/site">
       AllowOverride FileInfo Options Indexes Limit
       Options -Indexes -MultiViews +FollowSymLinks
   </Directory>
   ```
   Confirm `mod_proxy` and `mod_proxy_http` are loaded (`apachectl -M`); Plesk ships them
   enabled but they can be switched off under *Tools & Settings → Apache Web Server*.

2. **`site/.htaccess` — routing:**
   ```apache
   RewriteEngine On

   # Scheme for the Secure cookie decision downstream
   RequestHeader set X-Forwarded-Proto "https" env=HTTPS

   # Pretty auth-page paths (netlify.toml redirects)
   RewriteRule ^login$   /login.html  [L]
   RewriteRule ^signup$  /signup.html [L]

   # Protected paths -> Node. Order matters: these run before Apache
   # would map the URL to a file, so index.html is never served directly.
   RewriteRule ^$                 http://127.0.0.1:3000/            [P,L]
   RewriteRule ^index\.html$      http://127.0.0.1:3000/index.html  [P,L]
   RewriteRule ^files/(.*)$       http://127.0.0.1:3000/files/$1    [P,L]
   RewriteRule ^api/(.*)$         http://127.0.0.1:3000/api/$1      [P,L]

   # Nothing else in site/ is ever executable
   RemoveHandler .php .phtml .phar
   php_admin_flag engine off
   ```
   `[P]` needs `mod_proxy`; Apache returns 403 for `[P]` if the module is absent, which is
   the right failure. `mod_proxy` adds `X-Forwarded-For`, `X-Forwarded-Host` and
   `X-Forwarded-Server` automatically.

3. **`site/.htaccess` — headers**, copied from `netlify.toml`, applied only to responses Apache
   serves itself (the `!PROXIED` condition keeps them off Node's responses so CSP is never sent twice):
   ```apache
   SetEnvIf Request_URI "^/(index\.html)?$|^/files/|^/api/" PROXIED

   Header always set X-Frame-Options "SAMEORIGIN" env=!PROXIED
   Header always set X-Content-Type-Options "nosniff" env=!PROXIED
   Header always set Referrer-Policy "strict-origin-when-cross-origin" env=!PROXIED
   Header always set X-Robots-Tag "noindex, nofollow" env=!PROXIED
   Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com; frame-src 'self' https://login.microsoftonline.com; form-action 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'" env=!PROXIED
   Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
   Header unset X-Powered-By
   Header unset Server

   <FilesMatch "\.(html)$">
       Header set Cache-Control "no-store, must-revalidate"
   </FilesMatch>
   <FilesMatch "\.(css|js|png|jpg)$">
       Header set Cache-Control "public, max-age=604800"
   </FilesMatch>
   ```
   HSTS is set unconditionally because Node does not send it and it must be on every response.

4. **Running Node.** Two acceptable ways; pick one in §11.
   - **Plesk Node.js extension.** Create the app with *Application root* `httpdocs/`, *Document
     root* `httpdocs/public/` (an empty directory, **not** `site/`, so Passenger's own static-file
     serving cannot reach `index.html` or `protected/`), startup file `server.mjs`, mode
     `production`. The extension gives the app a URL under the domain; instead, the
     `.htaccess` proxies to the port Node listens on. Set `PORT=3000` explicitly in the
     app's environment so it is stable. Single instance.
   - **systemd unit** (`/etc/systemd/system/vtshub.service`): `ExecStart=/usr/bin/node
     /var/www/vhosts/hub.vts.edu/httpdocs/server.mjs`, `User=<plesk system user>`,
     `EnvironmentFile=/var/www/vhosts/hub.vts.edu/httpdocs/.env` (mode 0600, outside `site/`),
     `Restart=always`. Requires root once to install the unit.

5. **Fail closed on the file tree** (vhost-level, Plesk panel):
   ```apache
   <Directory "/var/www/vhosts/hub.vts.edu/httpdocs/protected">  Require all denied  </Directory>
   <Directory "/var/www/vhosts/hub.vts.edu/httpdocs/netlify">    Require all denied  </Directory>
   <Directory "/var/www/vhosts/hub.vts.edu/httpdocs/_source">    Require all denied  </Directory>
   ```
   These are outside the document root already; the directives are a second lock.

6. **PHP.** Not used. Turn *PHP support* off for the domain in Plesk (*PHP Settings*), in
   addition to the `.htaccess` line in 7.2, so a stray `.php` file in `site/` can never execute.

---

## 8. Environment variables

Set in the Plesk Node.js panel (*Custom environment variables*) or in the systemd
`EnvironmentFile`. Never in `site/`.

| Variable | Value | Notes |
|---|---|---|
| `NODE_ENV` | `production` | |
| `PORT` | `3000` | must match the `.htaccess` proxy target |
| `VTS_SESSION_SECRET` | output of `openssl rand -base64 48` | **Required.** Rotating it signs everyone out. Different value on staging |
| `AUTH_MODE` | `development` now, `entra` at switch-over | |
| `VTS_AUTH_STORE` | `mariadb` | new value, §5.2 (`file` if the JSON alternative is chosen) |
| `VTS_DB_HOST` / `VTS_DB_PORT` | `localhost` / `3306` | |
| `VTS_DB_NAME` / `VTS_DB_USER` / `VTS_DB_PASSWORD` | from Plesk *Databases* | user limited to the `vtshub` database |
| `VTS_FILES_DIR` | `/var/www/vhosts/hub.vts.edu/httpdocs/protected/files` | new, §5.1 |
| `VTS_ALLOW_PREVIEW` | `true` now, `false` at launch | |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_REDIRECT_URI` | from the app registration | public identifiers; also mirrored in `site/assets/config.js` |

No client secret exists and none is to be created.

---

## 9. Security requirements (parity checklist)

Each must be true on staging before cutover, verified with `curl -I` through the public URL:

- [ ] `GET /` without cookie → `302 Location: /login?next=%2F`
- [ ] `GET /index.html` without cookie → `302` (not a 200 from Apache or nginx)
- [ ] `GET /files/<any real doc>` without cookie → `401` "Sign-in required" HTML, `Cache-Control: private, no-store`
- [ ] Same request with "Serve static files directly by nginx" deliberately toggled on → still `401` (proves the documents are outside the docroot). Toggle it back off.
- [ ] `GET /files/../protected/x`, `GET /protected/…`, `GET /netlify/…`, `GET /_source/…`, `GET /site/index.html` → `403`/`404` (the last one proves the document root is `httpdocs/site`, not `httpdocs`)
- [ ] `GET /.htaccess`, `/.env`, `/server.mjs`, `/dev-server.mjs` → `403`/`404`
- [ ] `GET /login` → `200`, `Cache-Control: no-store, must-revalidate`, full CSP present **once**
- [ ] `GET /assets/app.js` → `200`, `nosniff`, CSP present once
- [ ] `GET /api/auth/me` → JSON from Node, CSP present once (from Node, not Apache)
- [ ] `POST /api/auth/login` with `Origin: https://evil.example` → CSRF rejection
- [ ] `POST /api/auth/login` with correct `Origin` → succeeds (proves `X-Forwarded-Host` handling)
- [ ] Sign-in `Set-Cookie` includes `HttpOnly; Secure; SameSite=Lax`
- [ ] `http://hub.vts.edu/` → `301` to https; HSTS on https responses
- [ ] No `Server: Apache/x.y`, no `X-Powered-By`; `GET /test.php` in `site/` is served as text or 403, never executed
- [ ] Sign out, press Back → login page, not the hub
- [ ] `node auth-tests.mjs` against staging: 98/98 (restart Node first to reset the limiter)
- [ ] Node log after first sign-up says `mariadb`, not the in-memory warning
- [ ] `vtshub` database is in the Plesk backup set

---

## 10. Operations and cutover

**Deploy process**
1. `git pull` (Plesk Git extension) or `rsync` to `httpdocs/`, excluding `_source/`, `.env`, `auth-tests.mjs`, `dev-server.mjs`.
2. `npm ci --omit=dev` in `httpdocs/` (only `mysql2`).
3. Restart Node (Plesk Node.js "Restart App" or `systemctl restart vtshub`).
4. Run the §9 curl checks. Roll back with `git checkout <previous tag>` and restart.

**Logging and monitoring**
- Node stdout → Plesk Node.js log, or `journalctl -u vtshub`. Apache/nginx logs as standard.
- Alert on the `[vts-auth] ... kept in memory` warning: it means MariaDB was unreachable and accounts are being lost.
- External uptime check on `GET /login` (expects 200) every 5 minutes.
- Let's Encrypt renewal alerts enabled.

**Backups**
- Plesk scheduled backup nightly including the `vtshub` database and `httpdocs/protected/`. Retain 14 days.

**Cutover sequence**
1. Build staging (`hub-staging.vts.edu`), pass §9.
2. Add `https://hub.vts.edu/` **and** the staging URL as SPA redirect URIs in Entra (replaces the Netlify preview URI in `setup-init.md` §1).
3. Lower DNS TTL for `hub.vts.edu` to 300 s at least 24 h ahead.
4. Set production env vars with a **new** `VTS_SESSION_SECRET`.
5. Export nothing from Netlify Blobs. Development accounts are throwaway; users re-register (announce this).
6. Repoint DNS; confirm certificate issued; re-run §9 against production.
7. Keep the Netlify site up but password-protected for 7 days, then delete it and remove its redirect URI from Entra.

---

## 11. Decisions needed before implementation

| # | Question | Recommendation |
|---|---|---|
| 1 | Move documents to `httpdocs/protected/files/`, or leave in `site/files/` and rely on rewrite rules alone? | **Move them.** Only the move survives a lost `.htaccess` or nginx static serving being switched back on |
| 2 | Account store: MariaDB or JSON file? | **MariaDB.** It is on the server, IT can inspect it, and it works with more than one Node process. Costs one npm dependency |
| 3 | Run Node via the Plesk Node.js extension or a systemd unit? | Plesk extension if IT wants everything in the panel; systemd if root access is routine. Either way, single instance on `127.0.0.1:3000` |
| 4 | Accept that assets go through Apache (nginx static serving off)? | Yes. The alternative is nginx `location` rules that must exactly mirror the `.htaccess`, which is a second place for the same security rules to drift |
| 5 | Serve documents inline or as downloads (`Content-Disposition`)? | Keep inline (current behaviour) unless VTS asks |
| 6 | Who owns the server (Plesk admin login, SSH, root)? | Needed before staging can start |
| 7 | Staging subdomain name and whether it needs its own Entra redirect URI | `hub-staging.vts.edu`, yes |

---

## 12. Effort estimate

| Work item | Estimate |
|---|---|
| `server.mjs` (forwarded-host handling, protected dir, header parity) | 0.5 day |
| MariaDB user store + tests | 0.5 day |
| Plesk domain, database, Node service, `.htaccess`, vhost directives, TLS | 0.5 day |
| Staging verification (§9) and `auth-tests.mjs` base-URL support | 0.5 day |
| Cutover, DNS, Entra URI update, Netlify decommission | 0.25 day |
| **Total** | **~2.25 days** plus waiting on DNS/Entra |
