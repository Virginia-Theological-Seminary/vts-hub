# VTS Hub

A password-protected section for vts.edu, restricted to Microsoft 365 accounts
in the **vts.edu** tenant. It replaces the faculty resource board currently on
`virginiatheological.mycampus-app.com`.

**Sign-in today:** Microsoft Entra is not registered yet, so the hub runs on a
**temporary development sign-in** — email and password accounts held by the site
itself, restricted to `@vts.edu` addresses. It is clearly labelled as temporary
wherever it appears, and it is designed to be swapped for Entra by changing one
environment variable. See [Authentication](#authentication) below.

---

## What still needs doing

| # | Item | Who |
|---|------|-----|
| 1 | Supply the 12 outstanding links and documents (list below) | VTS |
| 2 | Check the FY2022–23 HR and Finance documents are still current | HR / Finance |
| 3 | Register the app in Entra ID and paste two IDs into `site/assets/config.js` | VTS IT |
| 4 | Set `VTS_SESSION_SECRET` in Netlify | VTS IT / Ian |
| 5 | Deploy | Ian |
| 6 | Once 3 and 4 are done, set `AUTH_MODE=entra` to retire the temporary sign-in | Ian |

**15 of the 27 tiles are live.** The other 12 render as dashed, greyed-out
cards marked *Still to come*, so nothing looks finished when it isn't:

- Worship — prayer requests link, Links for Worship, policy documents, customaries
- Finance — check authorization form, travel expense report
- HR — faculty handbook, Shared Interest Program
- Systems — Paycom, Brightspace, Populi, Website Editor log-in URLs

The mycampus hub was never read directly (the browser extension was not
connected); everything here was built from documents supplied separately.

**A note on document currency:** the Staff Handbook, Employee Benefits Manual
and Travel Policy are all marked FY2022–23. Worth confirming with HR and
Finance that no newer versions exist before this goes live.

---

## 1. Register the application (VTS IT)

In the [Entra admin centre](https://entra.microsoft.com) → **App registrations**
→ **New registration**:

- **Name:** VTS Hub
- **Supported account types:** *Accounts in this organizational directory only
  (Virginia Theological Seminary only — Single tenant)* ← this is the setting
  that enforces "@vts.edu only"
- **Redirect URI:** platform **Single-page application (SPA)**, value = the
  site's address, e.g. `https://hub.vts.edu/`
  - Add a second SPA redirect URI for the Netlify preview address while testing.

No client secret is needed, and none should be created — a browser app cannot
keep one private. Authentication uses authorisation code flow with PKCE.

Under **API permissions**, `User.Read` (delegated) is present by default; that
is all that is required.

Then copy from the app's **Overview** page into `assets/config.js`:

```js
tenantId: "…Directory (tenant) ID…",
clientId: "…Application (client) ID…",
```

## 2. Set the session secret

In Netlify → **Site configuration → Environment variables**, add:

```
VTS_SESSION_SECRET = <a long random string>
```

Generate one with: `openssl rand -base64 48`

This signs the short-lived cookie that authorises document downloads. Without
it, sign-in still works but documents return "Sign-in required".

## 3. Deploy

Drag the whole `Website` folder onto Netlify (it publishes `site/`), or connect it to a repository.
`netlify.toml` and the two edge functions are picked up automatically.

Keep using the **same Netlify site** for redeploys so the URL, the Entra
redirect URI and the environment variable all stay valid.

---

## Authentication

The site talks to one auth layer and does not know which system is behind it.

```
VTS Hub
   |
   v
Auth Service                netlify/edge-functions/lib/auth-service.js
   |
   +-- DevelopmentAuth      temporary, in use now
   |
   +-- MicrosoftEntraAuth   production, not yet switched on
```

Swapping the two is one environment variable, `AUTH_MODE`. No page, route
guard or response body refers to how a password is checked or where accounts
are kept, so nothing in the hub has to change when Entra takes over.

### The temporary development sign-in

**This is not the VTS sign-in system.** It exists so the hub can be built and
demonstrated before IT has finished the Entra app registration. An account
created here has nothing to do with anyone's real VTS credentials, and the
sign-in and sign-up pages say so on screen.

- `/signup` — create an account. **`@vts.edu` addresses only**; the address is
  trimmed and lower-cased, then the part after the final `@` must be exactly
  `vts.edu`. Everything else is refused, including `a@vts.edu@gmail.com` and
  `user@vts.edu.example.com`.
- `/login` — sign in. The same domain rule is applied again.
- Passwords need 8+ characters with an upper-case letter, a lower-case letter,
  a number and a special character. The form shows the rules the server
  enforces, because it is sent the server's own list.
- New accounts get the role `student`. The sign-up form cannot ask for any
  other role — the request body's `role` field is never read.
- Passwords are hashed with **PBKDF2-HMAC-SHA-256, 210,000 iterations**, with a
  per-account random salt. Argon2id and bcrypt would both be better, but each
  needs a native or WASM module that the Netlify Edge runtime could only fetch
  from a third-party CDN at request time, and this project has no external
  runtime dependencies. The stored string is tagged with its algorithm and
  cost, so records upgrade themselves on the next sign-in if that changes.

Every rule above is enforced **on the server**. The browser repeats some of them
to give a quick, friendly message, but the server re-runs all of them and is
free to disagree.

### Sessions

Sign-in issues the **same signed HttpOnly cookie** the Entra path already
issued, in the same format — so `protect-files.js` guards `/files/*` for both
without a single change. The cookie is `HttpOnly`, `Secure`, `SameSite=Lax`,
and holds only `userId`, `email`, first and last name, role and expiry. A fresh
session id is minted on every sign-in, so a planted session cannot be adopted.
Sign out destroys it and returns to `/login`; the hub is served `no-store`, so
Back cannot redisplay it.

### The Microsoft button

Visible on both pages, disabled, marked **Coming Soon**, with the explanation
that Entra is still being configured. It has no click handler and no URL — it
cannot begin an authentication attempt, and nothing here contacts Microsoft.

### Switching to Entra

Once IT delivers the app registration:

1. Put the tenant and client IDs into `site/assets/config.js` (step 1 above).
2. Set `AUTH_MODE=entra` in the Netlify environment.

The Microsoft button becomes live, the password form disappears, and
`DevelopmentAuth` stops answering — it refuses both password paths under the
Entra provider, so no residue of the temporary system remains usable. To delete
it entirely, remove `lib/providers/development-auth.js`, `lib/user-store.js`,
`lib/password.js`, `site/login.html`, `site/signup.html` and their two assets;
nothing outside the auth layer refers to any of them.

### Where the development accounts live

Netlify Blobs, when it is available — no database to provision. When it is not
(the local dev server, or a site where Blobs cannot be reached), the store falls
back to memory and **logs a warning**, which means accounts do not survive a
restart. Check the edge-function log after the first deploy to see which one you
got. This limitation goes away with Entra, where Microsoft holds the accounts.

### Running it locally

The edge functions need a runtime. Either use `netlify dev`, or the small
zero-dependency server included here:

```bash
node dev-server.mjs
```

It serves `site/` and runs the same edge functions on the same paths, at
<http://localhost:8888>. A throwaway session secret is generated per run, and
accounts are held in memory. `dev-server.mjs` is not published — only `site/` is.

With that running, `auth-tests.mjs` exercises the whole thing — the sign-up and
sign-in rules, sessions and logout, and the security properties above:

```bash
node auth-tests.mjs
```

98 checks; start a fresh dev server before each run, or the sign-up rate limit
will refuse the later ones (which is the limiter working, and the suite says so
rather than reporting a failure).

### Configuration

`.env.example` lists every variable with placeholder values. Real values go in
Netlify under **Site configuration → Environment variables**; `.env` is
git-ignored and no secret belongs in the repository. There is **no client
secret** in this project and none should be created.

### Security notes

Handled: passwords hashed and never logged, returned or stored in plain text;
`HttpOnly` `Secure` `SameSite=Lax` cookies; CSRF on every state-changing request
(origin check plus double-submit token); session fixation (a new session id per
sign-in); open redirect (`?next=` accepts only a path on this site); user
enumeration (one message for a wrong password and a missing account, and the
same time spent on both); brute force (per-address lockout after 8 failed
sign-ins in 15 minutes); XSS (no user input reaches `innerHTML`, and a CSP with
no inline-script escape hatch); and injection (there is no query language —
lookups are exact-match reads of a hashed key).

Two things worth stating plainly rather than leaving to be discovered:

- **Rate limiting is per edge isolate.** Isolates are short-lived and there are
  many, so it raises the cost of guessing rather than making it impossible. A
  shared counter would need Blobs or a dedicated service; Entra brings
  Microsoft's own smart lockout, which is the real answer.
- **`/assets/data.js` is still public**, as it was before. The tile titles and
  link URLs can be read without signing in. The documents themselves cannot —
  `protect-files.js` guards every one of them. Closing this would mean putting
  the content behind the session too, which would also end `/?preview`.

`/?preview` still works exactly as it did: it renders the tile directory
without signing in, grants no access to any document, and stops working the
moment `AUTH_MODE=entra`. Set `VTS_ALLOW_PREVIEW=false` to turn it off sooner.

---

## How the protection works

There are three layers, and all of them matter:

**The screen.** Under Entra, `assets/app.js` uses MSAL to sign the user in
against the VTS tenant only, then re-checks that the address ends `@vts.edu`
(this catches guest accounts invited into the tenant). Under the temporary
development sign-in, the same job is done by `/login`. Until one of them
passes, the hub is not rendered.

**The page.** A check in the browser is a suggestion, not a control, so
`protect-app.js` refuses to serve `/` at all without a valid session and sends
the visitor to `/login`. It also sets `no-store`, which is what stops Back
redisplaying the hub after Sign out.

**The documents.** A screen-only gate would be theatre — the PDFs would still
be downloadable by anyone who guessed a URL. So after sign-in the browser posts
its Entra token to `/api/session`; the edge function verifies the token with
Microsoft, confirms the domain, and issues a signed HttpOnly cookie valid for
8 hours. Every request to `/files/*` is then checked by
`protect-files.js` before the file is served.

**A worthwhile alternative:** because VTS is already on Microsoft 365, the
documents could instead live in a SharePoint document library, with this site
holding only links. SharePoint then enforces access with the same accounts,
handles versioning, and lets the Finance and HR offices update their own forms
without touching the website. If VTS wants that, only `data.js` changes — the
`/files/` machinery can be dropped entirely.

---

## Editing the content

Everything on the page comes from **`assets/data.js`**. Each tile has a title,
an icon key, a kind (`doc` / `link` / `external`), and an `href`. Change a link,
add a form, reorder a section — it is all in that one file.

Icons live in `assets/icons.js` as inline SVG, keyed by name. Nothing is loaded
from a CDN, so the site has no external dependencies and will not break when
someone else's service goes away.

Items deliberately *not* moved across (faculty photographs, preacher links,
worship schedule, SoundCloud) are recorded at the bottom of `data.js` and shown
in the site footer, so the omission reads as a decision rather than an oversight.

---

## Files

Only `site/` is published. Everything outside it stays private.

```
site/index.html                          markup for the gate and the hub
site/login.html                          sign-in page
site/signup.html                         account creation page
site/assets/config.js                    the two IDs VTS IT fills in
site/assets/data.js                      all content — edit this
site/assets/icons.js                     inline SVG icon set
site/assets/app.js                       rendering; asks the auth layer who is signed in
site/assets/auth-client.js               the browser's only door to the auth layer
site/assets/auth-pages.js                sign-in / sign-up form behaviour
site/assets/styles.css                   styling (brand colour #293891)
site/assets/auth.css                     styling for the two auth pages, additive
site/assets/logo-full.jpg                stacked logo, used on the sign-in card
site/assets/logo-mark.jpg                the three windows, used in the masthead
site/assets/favicon.png                  the dove window, browser tab icon
site/vendor/msal-browser.min.js          Microsoft's auth library, vendored
site/files/                              the documents, protected by edge function

netlify/edge-functions/auth-api.js       /api/auth/* — the front end's only route
netlify/edge-functions/protect-app.js    guards the hub page
netlify/edge-functions/protect-files.js  guards /files/*
netlify/edge-functions/session.js        Entra token → signed cookie
netlify/edge-functions/lib/              the auth layer:
  auth-service.js                          the seam — picks the provider
  providers/development-auth.js            TEMPORARY, in use now
  providers/entra-auth.js                  production, not yet switched on
  validation.js                            the @vts.edu rule and password policy
  password.js                              PBKDF2 hashing
  session-token.js                         signed cookie, same format as session.js
  user-store.js                            development accounts (Blobs / memory)
  rate-limit.js                            brute-force limiting
  roles.js                                 role vocabulary and the default
  runtime.js                               env, cookies, base64url, timing-safe compare

netlify.toml                             headers, CSP, redirects; publishes site/ only
.env.example                             every variable, placeholder values only
dev-server.mjs                           local dev server, NOT published
auth-tests.mjs                           auth test suite, NOT published
_source/                                 original documents and briefs, NOT published
```

**Do not move the briefs or original documents back into `site/`** — anything
in there is served to the internet once the site is deployed.
