# VTS Hub

A password-protected section for vts.edu, restricted to Microsoft 365 accounts
in the **vts.edu** tenant. It replaces the faculty resource board currently on
`virginiatheological.mycampus-app.com`.

---

## What still needs doing

| #   | Item                                                                        | Who          |
| --- | --------------------------------------------------------------------------- | ------------ |
| 1   | Supply the 12 outstanding links and documents (list below)                  | VTS          |
| 2   | Check the FY2022–23 HR and Finance documents are still current              | HR / Finance |
| 3   | Register the app in Entra ID and paste two IDs into `site/assets/config.js` | VTS IT       |
| 4   | Set `VTS_SESSION_SECRET` in Netlify                                         | VTS IT / Ian |
| 5   | Deploy                                                                      | Ian          |

**15 of the 27 tiles are live.** The other 12 render as dashed, greyed-out
cards marked _Still to come_, so nothing looks finished when it isn't:

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
- **Supported account types:** _Accounts in this organizational directory only
  (Virginia Theological Seminary only — Single tenant)_ ← this is the setting
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

## How the protection works

There are two layers, and both matter:

**The screen.** `assets/app.js` uses MSAL to sign the user in against the VTS
tenant only, then re-checks that the address ends `@vts.edu` (this catches
guest accounts invited into the tenant). Until that passes, the hub is not
rendered.

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

Items deliberately _not_ moved across (faculty photographs, preacher links,
worship schedule, SoundCloud) are recorded at the bottom of `data.js` and shown
in the site footer, so the omission reads as a decision rather than an oversight.

---

## Files

Only `site/` is published. Everything outside it stays private.

```
site/index.html                          markup for the gate and the hub
site/assets/config.js                    the two IDs VTS IT fills in
site/assets/data.js                      all content — edit this
site/assets/icons.js                     inline SVG icon set
site/assets/app.js                       MSAL sign-in, domain check, rendering
site/assets/styles.css                   styling (brand colour #293891)
site/assets/logo-full.jpg                stacked logo, used on the sign-in card
site/assets/logo-mark.jpg                the three windows, used in the masthead
site/assets/favicon.png                  the dove window, browser tab icon
site/vendor/msal-browser.min.js          Microsoft's auth library, vendored
site/files/                              the documents, protected by edge function
netlify/edge-functions/session.js        token → signed cookie
netlify/edge-functions/protect-files.js  guards /files/*
netlify.toml                             headers; publishes site/ only
_source/                                 original documents and briefs, NOT published
```

**Do not move the briefs or original documents back into `site/`** — anything
in there is served to the internet once the site is deployed.
