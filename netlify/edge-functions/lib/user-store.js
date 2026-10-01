/* ------------------------------------------------------------------
   User store (TEMPORARY DEVELOPMENT AUTHENTICATION)
   ------------------------------------------------------------------
   Holds the development accounts. Three backends, chosen by
   VTS_AUTH_STORE — and never silently:

     mariadb   - the Plesk deployment. VTS_AUTH_STORE=mariadb plus the
                 VTS_DB_* variables. See store-mariadb.js.
     blobs     - Netlify, kept as a fallback host. Chosen automatically
                 when VTS_AUTH_STORE is unset and Blobs is reachable.
     memory    - local development only. Records live as long as the
                 process, which is stated loudly in the console.

   Fail-safe rules, learned the hard way (Bug 1: accounts vanished on
   every restart because the deployed code fell back to memory):
     - a requested backend that cannot be reached is an error, not a
       fallback;
     - an unknown VTS_AUTH_STORE value is an error;
     - with NODE_ENV=production, memory is refused outright, even when
       asked for by name.

   Records are keyed by SHA-256 of the normalised email, so the key
   space is fixed-width and safe, and the raw address is not part of a
   blob key. The email is stored inside the record. One-time tokens for
   password resets and email verification live alongside, keyed by the
   hash of the token.

   This whole module disappears when Microsoft Entra takes over — Entra
   is the account store at that point, and nothing here is needed.

   Injection: there is no SQL and no query language anywhere in this
   design. Lookups are exact-match reads of a hashed key, so an email
   is never interpolated into a query of any kind.
   ------------------------------------------------------------------ */

import { getStore } from "@netlify/blobs";
import { sha256Hex, randomId, env } from "./runtime.js";
import { mariadbBackend } from "./store-mariadb.js";

const STORE_NAME = "vts-hub-dev-auth";

/* ---------------- in-memory backend ---------------- */

const memory = new Map();
let warnedAboutMemory = false;

const memoryBackend = {
  kind: "memory",
  async get(key) {
    return memory.get(key) ?? null;
  },
  async insert(key, value) {
    if (memory.has(key)) return false;
    memory.set(key, value);
    return true;
  },
  async set(key, value) {
    memory.set(key, value);
  },
  async delete(key) {
    memory.delete(key);
  },
  async count() {
    return memory.size;
  },
  async listUsers() {
    return [...memory.entries()]
      .filter(([key]) => !key.startsWith("token:") && !key.startsWith("invite:"))
      .map(([, value]) => value);
  },
};

/* ---------------- Netlify Blobs backend ---------------- */

/* A static import, on purpose: Netlify bundles edge functions ahead of
   time and can only include a package it can see. The package is listed
   in package.json, so a Git-connected deploy installs it. Off Netlify —
   the local dev server, the test harness — getStore() throws because
   there is no Blobs context, and that is caught below. */
async function blobsBackend() {
  let store;
  try {
    store = getStore({ name: STORE_NAME, consistency: "strong" });
  } catch {
    return null;
  }

  /* Prove it actually works before committing to it — an unconfigured
     Blobs context throws on first use, and discovering that here means
     we can fall back cleanly instead of failing a sign-up. */
  try {
    await store.get("__probe__", { type: "text" });
  } catch {
    return null;
  }

  return {
    kind: "blobs",
    async get(key) {
      return (await store.get(key, { type: "json" })) ?? null;
    },
    async insert(key, value) {
      if ((await store.get(key, { type: "json" })) != null) return false;
      await store.setJSON(key, value);
      return true;
    },
    async set(key, value) {
      await store.setJSON(key, value);
    },
    async delete(key) {
      await store.delete(key);
    },
    async count() {
      try {
        const { blobs } = await store.list();
        return blobs.length;
      } catch {
        return null;
      }
    },
    async listUsers() {
      const { blobs } = await store.list();
      const users = [];
      for (const blob of blobs) {
        if (blob.key.startsWith("token:") || blob.key.startsWith("invite:")) continue;
        const value = await store.get(blob.key, { type: "json" });
        if (value) users.push(value);
      }
      return users;
    },
  };
}

let backendPromise = null;

function isProduction() {
  return String(env("NODE_ENV", "")).toLowerCase() === "production";
}

function warnMemory() {
  if (warnedAboutMemory) return;
  warnedAboutMemory = true;
  console.warn(
    "[vts-auth] Accounts are being kept IN MEMORY and will not survive a restart. " +
      "Fine for local development; never for a deployed site. " +
      "Set VTS_AUTH_STORE=mariadb (Plesk) or leave it unset on Netlify (Blobs)."
  );
}

/* One decision, made explicitly. Every branch either returns a working
   backend or throws with a message that says what to configure. */
async function chooseBackend() {
  const requested = String(env("VTS_AUTH_STORE", "")).toLowerCase().trim();

  switch (requested) {
    case "mariadb":
      return mariadbBackend();

    case "blobs": {
      const blobs = await blobsBackend();
      if (!blobs) throw new Error("VTS_AUTH_STORE=blobs but Netlify Blobs is not reachable here");
      return blobs;
    }

    case "memory":
      if (isProduction()) {
        throw new Error(
          "VTS_AUTH_STORE=memory is refused when NODE_ENV=production: accounts would be " +
            "lost on every restart. Set VTS_AUTH_STORE=mariadb."
        );
      }
      warnMemory();
      return memoryBackend;

    case "": {
      /* Unset: Netlify's Blobs if this is Netlify; otherwise memory —
         but only outside production. A deployed site must say what it
         wants. */
      const blobs = await blobsBackend();
      if (blobs) return blobs;
      if (isProduction()) {
        throw new Error(
          "No account store configured. Set VTS_AUTH_STORE=mariadb and the VTS_DB_* " +
            "variables (NODE_ENV=production refuses the in-memory store)."
        );
      }
      warnMemory();
      return memoryBackend;
    }

    default:
      throw new Error(
        'Unknown VTS_AUTH_STORE "' + requested + '". Valid values: mariadb, blobs, memory.'
      );
  }
}

/* The chosen backend is cached for the life of the process. A failure
   is NOT cached: if the database was unreachable for one request, the
   next request tries again rather than being broken forever. */
async function backend() {
  if (!backendPromise) {
    backendPromise = chooseBackend().catch((err) => {
      backendPromise = null;
      throw err;
    });
  }
  return backendPromise;
}

/* Called once at startup by the server so a misconfigured store stops
   the process with a clear message instead of failing the first
   sign-up. Returns the backend kind. */
export async function ensureStore() {
  return (await backend()).kind;
}

/* ---------------- record shape ---------------- */

const keyFor = async (email) => (await sha256Hex("user:" + email)).slice(0, 40);

export async function findUserByEmail(email) {
  const store = await backend();
  return store.get(await keyFor(email));
}

/* Creates the record. The caller has already validated the email and
   hashed the password; this function never sees a plaintext password
   and stores only `passwordHash`. */
export async function createUser({
  email,
  passwordHash,
  firstName,
  lastName,
  role,
  /* When the address counts as confirmed. Optional and defaulting to
     null, so every existing caller behaves exactly as before; the
     provider passes a timestamp when email verification is switched
     off and the account is usable from the moment it is created. */
  emailVerifiedAt = null,
  /* PBKDF2 hash of the recovery code issued at sign-up — the proof
     required to reset a password while there is no working email.
     Optional, so callers predating it are unaffected. */
  recoveryCodeHash = null,
  /* Whether a confirmation was asked of THIS account. Distinct from
     emailVerifiedAt being null, which is also true of accounts made
     before anyone asked — those must not be locked out when the policy
     changes. Defaults to false, so records predating the field read
     as "nothing was ever asked of it", which is what they are. */
  verificationPending = false,
}) {
  const store = await backend();
  const key = await keyFor(email);

  const user = {
    id: "usr_" + randomId(12),
    email,
    passwordHash,
    firstName,
    lastName,
    role,
    /* Set when the holder proves they can read mail at this address —
       or at creation, when verification is not required. Null means the
       account exists but cannot sign in. */
    emailVerifiedAt,
    verificationPending: Boolean(verificationPending),
    recoveryCodeHash,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  /* Create-only write: the backend refuses a duplicate key, so two
     simultaneous sign-ups for one address cannot both succeed. */
  if (!(await store.insert(key, user))) return { ok: false, reason: "exists" };
  return { ok: true, user };
}

export async function updateUser(email, patch) {
  const store = await backend();
  const key = await keyFor(email);
  const current = await store.get(key);
  if (!current) return null;
  const next = { ...current, ...patch, email: current.email, id: current.id, updatedAt: new Date().toISOString() };
  await store.set(key, next);
  return next;
}

/* ---------------- invitations ---------------- */

/* Issued by an administrator for one named address; see invite.js.
   Stored under a key derived from the address, so issuing a second
   invitation replaces the first rather than leaving two live. Only the
   hash of the code is kept. */
export async function putInvite(email, { codeHash, issuedAt }) {
  const store = await backend();
  const { inviteKeyFor } = await import("./invite.js");
  await store.set(await inviteKeyFor(email), { email, codeHash, issuedAt });
}

export async function findInvite(email) {
  const store = await backend();
  const { inviteKeyFor } = await import("./invite.js");
  return store.get(await inviteKeyFor(email));
}

/* Redeeming removes it: an invitation opens one account, once. */
export async function takeInvite(email) {
  const store = await backend();
  const { inviteKeyFor } = await import("./invite.js");
  const key = await inviteKeyFor(email);
  const record = await store.get(key);
  if (record) await store.delete(key);
  return record;
}

/* Every account, for the administration tool. Not reachable from any
   route: nothing in auth-api.js calls it, and it is not something an
   unauthenticated caller could ever be allowed to ask for. */
export async function listUsers() {
  const store = await backend();
  if (!store.listUsers) return [];
  const users = await store.listUsers();
  return users.sort((a, b) => String(a.email).localeCompare(String(b.email)));
}

/* Removes an account outright. Used when a sign-up cannot be completed
   — the verification mail is refused, say — so the address is left free
   for the person to try again, rather than occupied by a record they
   can neither use nor replace. Not a general "delete my account"
   feature: that would need its own confirmation flow. */
export async function deleteUser(email) {
  const store = await backend();
  await store.delete(await keyFor(email));
}

/* ---------------- one-time tokens ---------------- */

/* Used for both password resets and email verification. The token
   itself is never stored — only its SHA-256, the same way a password is
   never stored — so a copy of the store cannot redeem anyone's link.
   Each record names the account, the purpose it was minted for, and
   when it stops being valid. */
const tokenKeyFor = async (tokenHash) => "token:" + tokenHash.slice(0, 40);

export async function putToken(tokenHash, { email, purpose, expiresAt }) {
  const store = await backend();
  await store.set(await tokenKeyFor(tokenHash), { email, purpose, expiresAt });
}

/* Read-and-delete. A link works exactly once: a second click, or a
   replay of a captured link, finds nothing. A token minted for one
   purpose cannot be redeemed for another — a verification link does
   not reset a password. Expired and mismatched records are deleted on
   the way out, so they never accumulate. */
export async function takeToken(tokenHash, purpose) {
  const store = await backend();
  const key = await tokenKeyFor(tokenHash);
  const record = await store.get(key);
  if (!record) return null;
  await store.delete(key);
  if (record.purpose !== purpose) return null;
  if (!record.expiresAt || Date.now() > record.expiresAt) return null;
  return record;
}

/* Strips the credential material. Nothing that reaches a response body
   or a session should come from anywhere but this function. */
export function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName || "",
    lastName: user.lastName || "",
    role: user.role,
    emailVerified: Boolean(user.emailVerifiedAt),
    createdAt: user.createdAt,
  };
}

/* Releases the backend's resources. Long-running servers never call
   this — they keep the pool for the life of the process — but a
   command-line tool has to, or Node stays alive holding an idle
   database connection and the command appears to hang. */
export async function closeStore() {
  if (!backendPromise) return;
  const store = await backendPromise.catch(() => null);
  backendPromise = null;
  if (store && typeof store.close === "function") await store.close();
}

export async function storeKind() {
  return (await backend()).kind;
}

/* Test seam only — lets the harness start from a known state. */
export async function __resetMemoryStore() {
  memory.clear();
  backendPromise = null;
  warnedAboutMemory = false;
}
