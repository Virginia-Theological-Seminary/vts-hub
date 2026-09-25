# VTS Hub

A password-protected section for vts.edu, restricted to Microsoft 365 accounts
in the **vts.edu** tenant. It replaces the faculty resource board currently on
`virginiatheological.mycampus-app.com`.

**Sign-in today:** Microsoft Entra is not registered yet, so the hub runs on a
**temporary development sign-in** — email and password accounts held by the site
itself, restricted to `@vts.edu` addresses, each confirmed by a link sent to that
address. It is labelled as temporary wherever it appears in the code, and it is
designed to be swapped for Entra by changing one environment variable. It runs
for real on Ironistic's Plesk server — `hub.vts.edu`, with `dev-vtshub.vts.edu`
for testing — see [Going live without Entra](#going-live-without-entra) and
[Deploying a release](#deploying-a-release). Netlify is kept only as a fallback
host.

---

## What still needs doing

| # | Item | Who |
|---|------|-----|
| 1 | Supply the 12 outstanding links and documents (list below) | VTS |
| 2 | Check the FY2022–23 HR and Finance documents are still current | HR / Finance |
| 3 | Register the app in Entra ID and paste two IDs into `site/assets/config.js` | VTS IT |
| 4 | Set `VTS_SESSION_SECRET` in Netlify | VTS IT / Ian |
| 5 | Deploy — see [Deploying a release](#deploying-a-release) | Ironistic (JT) |
| 6 | Until 3 is done: publish the Resend DNS records for `hub.vts.edu`, set `MAIL_FROM` to an address on it, and set `VTS_AUTH_STORE=mariadb` + `VTS_DB_*` on both Plesk sites (see [Going live](#going-live-without-entra)) | Ironistic (JT) |
| 7 | Once 3 and 4 are done, set `AUTH_MODE=entra` to retire the temporary sign-in | Ian |

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

In Plesk → **Node.js** (the app) → **Custom environment variables**, add:

```
VTS_SESSION_SECRET = <a long random string>
```

Generate one with: `openssl rand -base64 48`. Use a different value on
`dev-vtshub` and `hub`.

This signs the session cookie. Without it the server refuses to start in
production — a throwaway secret would sign everyone out on every restart.
Rotating it deliberately does the same, which is the emergency "sign everyone
out" lever.

## 3. Deploy

The site runs on Ironistic's Plesk server under Passenger. Full setup is in
[Going live without Entra](#going-live-without-entra); the short version of
every subsequent release is in [Deploying a release](#deploying-a-release).
`plesk-migration-requirements.md` is Ironistic's own specification for the
hosting.

Netlify is kept as a fallback host only: `netlify.toml` and the
`netlify/edge-functions/` layout still work there unchanged (accounts go to
Netlify Blobs), but nothing is deployed to it today.

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
used before IT has finished the Entra app registration. An account created here
has nothing to do with anyone's real VTS credentials; the Microsoft button on
the sign-in and sign-up pages says Entra is still being configured.

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
- **Sign-up asks for proof that the address is yours.** The domain rule only
  checks the *shape* of an address, so on its own it would let anyone register
  `dean@vts.edu`. One of two things supplies the missing proof:

  | Policy | How it proves it | In force when |
  |---|---|---|
  | `email` | a one-time confirmation link, valid 24 hours; the account cannot sign in until `/verify` redeems it | mail can actually be delivered |
  | `invitation` | a code issued per address, out of band, by `npm run account -- --invite` | mail cannot |

  **The server chooses between them, and re-chooses on every restart.** A
  confirmation link only proves anything if mail genuinely leaves the server, so
  at startup it asks the mail provider whether a message can reach anybody other
  than the mail account's own owner, and sets the policy from the answer. The
  startup log says which is in force and why:

  ```
  sign-up  by invitation — npm run account -- --invite someone@vts.edu
           (auto: MAIL_FROM uses Resend's test sender, which Resend delivers
           ONLY to the address that owns the Resend account)
  ```

  Today that answer is *no* — the sending domain's DNS records are not published
  (see [Going live](#going-live-without-entra)) — so sign-up is by invitation.
  **The day those records are published, the next restart moves to email
  confirmation on its own**: no code change, no deploy, and no moment in which
  sign-up is open with neither proof in force. `VTS_SIGNUP_POLICY` pins either
  one if you need to; requiring confirmation while mail is broken would make
  sign-up impossible rather than safer, which is why `auto` is the default.

  Anyone stranded mid-confirmation — signed up while a link was required, never
  received it — is confirmed by hand with `npm run account -- --verify`, after a
  human has checked who they are. An account created *before* anything asked for
  a confirmation is not one that owes a confirmation, and changing the policy
  never locks those out.
- Passwords are hashed with **PBKDF2-HMAC-SHA-256, 210,000 iterations**, with a
  per-account random salt. Argon2id and bcrypt would both be better, but each
  needs a native or WASM module that the Netlify Edge runtime could only fetch
  from a third-party CDN at request time, and this project has no external
  runtime dependencies. The stored string is tagged with its algorithm and
  cost, so records upgrade themselves on the next sign-in if that changes.

Every rule above is enforced **on the server**. The browser repeats some of them
to give a quick, friendly message, but the server re-runs all of them and is
free to disagree.

### Forgot password

Resetting a password has to prove the person asking owns the account —
otherwise anyone who knew an address could take one that already exists, which
is worse than sign-up being open. That proof is a **recovery code**, not a
mailed link, so it works whether or not mail does.

- The code is issued **once, at sign-up**, in the shape
  `VTSH-XXXX-XXXX-XXXX-XXXX`. It is shown on screen immediately after the
  account is created and **never again**: only a PBKDF2 hash of it is stored, so
  nobody — including whoever runs the server — can produce it later.
- `/reset` takes the address, the code and a new password. `/forgot` is a
  signpost to it, not a form: there is nothing to send.
- A typo in the new password does not burn the code — the password is checked
  **before** the code is consumed.
- The code works **once**, and a fresh one is issued in the same write, so the
  holder is never left without a way back in and a code read over a shoulder is
  worthless after use. Attempts per address are rate limited.
- A reset **ends every session that existed at the time**, including one held by
  whoever made the reset necessary, and clears any sign-in lockout on the
  address. The user is sent to `/login` to prove the new password by using it.
- A reset does **not** confirm the address. The code proves possession of the
  code, not that anyone can read mail at the address; letting it confer
  confirmation would hand an unconfirmed account a way to confirm itself.
- Lost the code, with no way to prove anything? That needs a human:
  `npm run account -- --code someone@vts.edu` issues a new one and prints it,
  for an administrator to hand over having checked who they are talking to. The
  administrator never sees or chooses anyone's password.

**How confirmation links get to the user** is decided in `lib/mailer.js`, in
this order:

- On the **local dev server**, every message is captured and shown at
  `/__dev/outbox` (the way Mailpit would). The pages link to it.
- With **`RESEND_API_KEY` and `MAIL_FROM` set**, mail is sent through
  [Resend](https://resend.com) over its HTTPS API. Nothing is installed; it is one
  `fetch()`. See [Going live](#going-live-without-entra) for the setup.
- **Otherwise**, the message is written to the edge-function log, which site
  collaborators can read and pass on. Crude, but secure: the link never goes back
  to the browser that asked for it.

The same module answers the question the sign-up policy turns on — *can a
message reach anybody but the mail account's own owner?* — so the policy and the
startup warnings can never disagree. The local outbox deliberately answers
**no**: it captures messages, it does not deliver them, and a development server
that behaved unlike the server it stands in for would be worse than useless. To
work on the confirmation flow locally, set `VTS_SIGNUP_POLICY=email` and read
the link in the outbox.

Swapping Resend for another provider is the body of one function. Under Entra
none of this is used: Microsoft confirms addresses by their existing and handles
forgotten passwords itself.

One limit worth knowing: `protect-files.js` checks a session's signature and
expiry only, so a session that existed before a reset can still open a document
until it expires (8 hours at most). The hub page and every API route refuse it
immediately. Closing that gap would mean the untouched Entra-era file consulting
the temporary user store, which is the wrong direction.

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

`VTS_AUTH_STORE` decides, and the choice is never silent:

| Value | Where | When |
|---|---|---|
| `mariadb` | a MariaDB table, `vts_hub_store` | **the Plesk deployment** — set `VTS_DB_HOST/PORT/NAME/USER/PASSWORD` |
| `blobs` / unset on Netlify | Netlify Blobs | the Netlify fallback host |
| `memory` / unset elsewhere | the process's memory | **local development only** — accounts vanish on restart |

Three rules, learned from the September 2026 incident where every account
disappeared on each Passenger restart because the deployed code had quietly
fallen back to memory:

- a backend that is asked for but cannot be reached is an **error**, not a
  fallback — the server refuses to start and says why;
- an unknown value is an error;
- with `NODE_ENV=production`, memory is refused even when asked for by name.

The table holds one JSON record per key: the account (password **hash** only,
names, role, `emailVerifiedAt`, `passwordChangedAt`, timestamps) or a one-time
token (by its hash). It is created on first start and can be inspected from the
Plesk database panel:

```sql
SELECT JSON_VALUE(v,'$.email') AS email, JSON_VALUE(v,'$.role') AS role,
       JSON_VALUE(v,'$.emailVerifiedAt') IS NOT NULL AS verified, updated_at
FROM vts_hub_store WHERE kind = 'user';
```

Nothing in it can be used to sign in. It is dropped when Entra takes over.

### Administering accounts

`npm run account` is a command-line tool for whoever has access to the server.
It is not published and not served — only `site/` is — and it refuses to run
against the in-memory store, where it would be editing a copy that disappears.

```bash
npm run account -- --list                      # every account, and which cannot sign in yet
npm run account -- --invite someone@vts.edu    # let that address create an account
npm run account -- --verify someone@vts.edu    # confirm an address by hand
npm run account -- --code   someone@vts.edu    # issue a replacement recovery code
npm run account -- --delete someone@vts.edu    # remove an account
```

`--invite` and `--verify` are two halves of the same job under the two sign-up
policies, and the tool refuses whichever one is not in force rather than
handing over a code that would silently do nothing.

Confirming who you are talking to is the human's job here. The tool cannot do
it, and a code given to the wrong person is a given-away account. Note what
`--code` deliberately does *not* do: it never sets anyone's password. The
administrator hands over a code, the account holder chooses their own password
at `/reset`, and nobody but the holder has ever held it.

Retires with Entra, where accounts and forgotten passwords are Microsoft's
business.

### Database migrations

`database-migrate/` holds the account store's structure as code, so the
table on a new Plesk site is created deliberately rather than by the
application's first start. Each migration is one file,
`database-migrate/migrations/migration-<uuid>.mjs`, exporting `up(db)` and
`down(db)`; applied migrations are recorded in `vts_hub_migrations` so none
runs twice. Connection settings are the same `VTS_DB_*` variables the
application uses, from the environment or `.env`.

```bash
npm run db -- --status                     # applied and pending
npm run db -- --migration <uuid>           # apply one
npm run db -- --migration <uuid> --down    # undo one (drops the table — accounts go with it)
npm run db -- --all                        # apply every pending one, oldest first
npm run db -- --new "what it changes"      # write a new migration-<uuid>.mjs to fill in
npm run db --migration=<uuid>              # the npm-side spelling also works
```

The first migration, `1a88af9c-8dd0-4614-b385-493775e962bd`, builds
`vts_hub_store` from a description of its columns and indexes. It checks
`information_schema` first, so on a database where `store-mariadb.js`
already created the table it adds anything missing and touches no row.
On a fresh Plesk site, run it after `npm ci` and before the first Restart
App:

```bash
npm run db -- --migration 1a88af9c-8dd0-4614-b385-493775e962bd
```

### Running it locally

The edge functions need a runtime. Either use `netlify dev`, or the small
server included here. One install first, for the Blobs client:

```bash
npm install
```

```bash
node dev-server.mjs
```

It serves `site/` and runs the same edge functions on the same paths, at
<http://localhost:8888>. A throwaway session secret is generated per run, and
accounts are held in memory. Mail the site tries to send is captured at
`/__dev/outbox` — the pages say so under their "check your email" message, and
only there; on the deployed site that line never appears. To test real delivery
from the laptop, put the Resend values in `.env` and set `VTS_MAIL_OUTBOX=false`.
`dev-server.mjs` is not published — only `site/` is.

With that running, `auth-tests.mjs` exercises the whole thing — the sign-up and
sign-in rules, sessions and logout, and the security properties above:

```bash
node auth-tests.mjs
```

155 checks; start a fresh dev server before each run, or the sign-up rate limit
will refuse the later ones (which is the limiter working, and the suite says so
rather than reporting a failure).

### Configuration

`.env.example` lists every variable with placeholder values. Real values go in
Netlify under **Site configuration → Environment variables**; `.env` is
git-ignored and no secret belongs in the repository. There is **no client
secret** in this project and none should be created.

### Going live without Entra

The site runs on Ironistic's Plesk server (`hub.vts.edu`, with
`dev-vtshub.vts.edu` for testing); Netlify is kept only as a fallback host.
`plesk-migration-requirements.md` is Ironistic's own specification for the
hosting; this section is the application's side of it.

1. **Plesk → Node.js app.** Application root `httpdocs`; **document root
   `httpdocs/public`, an empty folder** — not `site/`. With `site/` as the
   document root, Apache serves `/files/*.pdf` and the hub page straight from
   disk and the sign-in check never runs. Startup file `dev-server.mjs`
   (`server.mjs` when it lands); mode `production`; Node 22. After `git pull`:
   `npm ci`, then Restart App.

2. **Environment variables** (Plesk → Node.js → *Custom environment
   variables*; the same set on dev and production, different values):

   | Variable | Value |
   |---|---|
   | `NODE_ENV` | `production` — makes the server refuse to start misconfigured |
   | `VTS_SESSION_SECRET` | `openssl rand -base64 48`, a different value per site |
   | `AUTH_MODE` | `development` |
   | `VTS_AUTH_STORE` | `mariadb` |
   | `VTS_DB_HOST` / `VTS_DB_PORT` | `localhost` / `3306` |
   | `VTS_DB_NAME` / `VTS_DB_USER` / `VTS_DB_PASSWORD` | from Plesk → Databases |
   | `VTS_SITE_URL` | the site's public address, e.g. `https://hub.vts.edu` |
   | `VTS_ALLOW_PREVIEW` | `false` |
   | `VTS_MAIL_OUTBOX` | `false` — **required**; the server will not start otherwise |
   | `RESEND_API_KEY` | from the Resend account |
   | `MAIL_FROM` | an address on the domain verified in Resend, e.g. `VTS Hub <noreply@hub.vts.edu>` |

   Do not set `PORT`; Passenger provides it.

3. **Verify a sending domain in Resend.** In Resend → *Domains*, add the domain
   (`hub.vts.edu` is already added) and publish the DNS records it shows — a DKIM
   `TXT` on `resend._domainkey.<domain>` and two `CNAME`s on `send.<domain>` and
   `rsend.<domain>`. **The `vts.edu` zone is held by FDS** (the nameservers are
   `ns1`/`ns2.focusdatasolutions.com`), not by Ironistic, who host the site —
   asking the wrong one of the two costs days. Until Resend shows the domain
   **verified**, nobody but the Resend account's owner receives any mail: the test
   sender `onboarding@resend.dev` is refused for every other recipient, and an
   unverified domain is refused for everyone. That was the September 2026 "my
   colleague never got the email" incident. The server names either condition
   in its startup log as a `mail WARNING`.

   Publishing these records does one more thing: at the next restart the server
   sees that mail can reach anybody, and sign-up moves from invitation codes to
   email confirmation by itself. Expect the `sign-up` line in the startup log to
   change, and expect to stop issuing invitations.

4. **Read the startup log after every deploy.** Five lines matter:

   ```
   mode     production
   store    mariadb — accounts persist
   mail     sending for real through Resend, from VTS Hub <noreply@hub.vts.edu>
   mail     Resend domain hub.vts.edu verified — mail can reach any address
   sign-up  open to any @vts.edu address, confirmed by email (auto: ...)
   ```

   `store memory`, or any `FATAL` or `mail WARNING` line, means the site is
   not ready for real users.

5. **Verify from outside:**

   ```bash
   H=https://hub.vts.edu
   curl -sI $H/                                        # 302 -> /login
   curl -sI $H/files/hr/staff-handbook-fy2022-23.pdf   # 401
   curl -sI $H/__dev/outbox                            # 404
   curl -s  $H/api/auth/context | grep -o '"delivery":"[a-z]*"' | head -1   # "email"
   ```

What you have at that point: durable `@vts.edu`-only accounts, each confirmed by
email, with self-service password reset, on the site's real address. What you do
not have, and only Entra brings: MFA, conditional access, central deprovisioning
when someone leaves, and Microsoft's own lockout protection. When the
registration lands, steps 1–2 of this README plus `AUTH_MODE=entra` retire all
of this in one deploy.

### Deploying a release

Every release, on `dev-vtshub` first and then `hub`:

1. `git pull` in `httpdocs/` (the branch the site tracks).
2. `npm ci` — installs exactly what `package-lock.json` says.
3. **Restart App** in Plesk → Node.js.
4. **Read the startup log.** It must contain, and nothing marked `FATAL` or
   `WARNING`:

   ```
   mode     production
   store    mariadb — accounts persist
   mail     sending for real through Resend, from VTS Hub <noreply@hub.vts.edu>
   mail     Resend domain hub.vts.edu verified — mail can reach any address
   ```

   A `FATAL` line means the server did not start, and the line says what to
   set. A `mail WARNING` means it started but nobody except the Resend
   account's owner will receive email.

5. Run the five `curl` checks in [Going live](#going-live-without-entra) step 5.
6. Sign in once with a real account.

Accounts and one-time tokens are in the database, so a release never signs
anyone out or loses anyone's password. Only rotating `VTS_SESSION_SECRET` does
the former; nothing does the latter.

### Troubleshooting

Symptom first, because that is how it arrives.

| Symptom | Cause | Fix |
|---|---|---|
| "My password worked yesterday and doesn't today" / everyone has to sign up again | The store is **memory**: the startup log says `store memory`, or the server was deployed before September 2026 | `VTS_AUTH_STORE=mariadb` + `VTS_DB_*`, restart. Accounts made while on memory are gone; people sign up once more. |
| Server will not start: `FATAL Account store unavailable` | MariaDB unreachable, wrong credentials, or `VTS_DB_*` incomplete | The line quotes the driver's reason (`ECONNREFUSED`, `Access denied`…). Check Plesk → Databases. This is deliberate: it will not fall back to memory. |
| Server will not start: `FATAL ... dev mail outbox` | `VTS_MAIL_OUTBOX` unset or `true` in production | Set it to `false`. The outbox would publish every reset link. |
| I get the emails; a colleague does not | `mail WARNING: MAIL_FROM uses Resend's test sender` — Resend delivers `onboarding@resend.dev` only to the account owner | Verify a domain in Resend (DNS records) and set `MAIL_FROM` to an address on it |
| Nobody gets emails, sign-up says "couldn't send the confirmation email" | `mail WARNING: ... status is 'failed'` — the domain is added in Resend but its DNS records are not published, or `WARNING: ... is not added in Resend` | Publish the three records Resend shows; wait for status **verified** |
| Forgot-password says "sent" but nothing arrives | Same as above. The forgot page answers identically whether or not the address exists, by design, so the failure is only in the log | Look for `[vts-mail] Resend rejected the message` in the app log |
| `/files/*.pdf` open without signing in; `/` shows the hub without sign-in | The Plesk app's document root is `httpdocs/site`, so Apache serves files itself | Document root → `httpdocs/public` (empty folder); restart |
| `/__dev/outbox` exists on a deployed site | Outbox on (see above) | `VTS_MAIL_OUTBOX=false`; the route then returns 404 |
| Sign-in POST fails with the "session expired while this page was open" message | CSRF check: the `Origin` header's host does not match what the server thinks its own host is (proxy without `X-Forwarded-Host`) | Pending `server.mjs`; until then the app must be reached on the host Passenger sees |
| "Too many attempts" on the first try | Someone else behind the same address tripped the per-address limiter, or the app was restarted mid-test | Wait 15 minutes; restarting the app also clears it |

### Security notes

Handled: passwords hashed and never logged, returned or stored in plain text;
address ownership proven by a single-use confirmation link before an account can
sign in; password reset via single-use, hashed, 30-minute tokens; no account
enumeration on any of the request forms;
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
site/forgot.html                         request a password-reset link
site/reset.html                          choose a new password from a link
site/verify.html                         confirm an address from a link
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
  user-store.js                            development accounts + one-time tokens; picks the backend
  store-mariadb.js                         the MariaDB backend (Plesk)
  mailer.js                                how mail leaves the site (outbox / Resend / log)
  rate-limit.js                            brute-force limiting
  roles.js                                 role vocabulary and the default
  runtime.js                               env, cookies, base64url, timing-safe compare

netlify.toml                             headers, CSP, redirects; publishes site/ only
database-migrate/migrate.mjs             migration runner and generator (npm run db), NOT published
database-migrate/migrations/             one migration-<uuid>.mjs per structure change
package.json                             the one dependency (@netlify/blobs); npm scripts
.env.example                             every variable, placeholder values only
dev-server.mjs                           local dev server, NOT published
auth-tests.mjs                           auth test suite, NOT published
_source/                                 original documents and briefs, NOT published
```

**Do not move the briefs or original documents back into `site/`** — anything
in there is served to the internet once the site is deployed.
