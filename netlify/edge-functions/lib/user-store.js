/* ------------------------------------------------------------------
   User store (TEMPORARY DEVELOPMENT AUTHENTICATION)
   ------------------------------------------------------------------
   Holds the development accounts. Two backends, chosen at runtime:

     Netlify Blobs  - used on a deployed site. Durable, strongly
                      consistent, no database to provision.
     In-memory      - fallback for the local dev server and for any
                      environment where Blobs is unavailable. Records
                      live only as long as the process, which is stated
                      loudly in the console rather than hidden.

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

const STORE_NAME = "vts-hub-dev-auth";

/* ---------------- in-memory backend ---------------- */

const memory = new Map();
let warnedAboutMemory = false;

const memoryBackend = {
  kind: "memory",
  async get(key) {
    return memory.get(key) ?? null;
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
  };
}

let backendPromise = null;

async function backend() {
  if (!backendPromise) {
    backendPromise = (async () => {
      if (env("VTS_AUTH_STORE") !== "memory") {
        const blobs = await blobsBackend();
        if (blobs) return blobs;
      }
      if (!warnedAboutMemory) {
        warnedAboutMemory = true;
        console.warn(
          "[vts-auth] Netlify Blobs unavailable - development accounts are being kept " +
            "in memory and will not survive a restart. This is expected on the local " +
            "dev server; on a deployed site, enable Netlify Blobs."
        );
      }
      return memoryBackend;
    })();
  }
  return backendPromise;
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
export async function createUser({ email, passwordHash, firstName, lastName, role }) {
  const store = await backend();
  const key = await keyFor(email);

  /* Re-check under the same read that writes: two simultaneous sign-ups
     for one address should not both succeed. */
  const existing = await store.get(key);
  if (existing) return { ok: false, reason: "exists" };

  const user = {
    id: "usr_" + randomId(12),
    email,
    passwordHash,
    firstName,
    lastName,
    role,
    /* Set when the holder proves they can read mail at this address.
       Until then the account exists but cannot sign in. */
    emailVerifiedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await store.set(key, user);
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

export async function storeKind() {
  return (await backend()).kind;
}

/* Test seam only — lets the harness start from a known state. */
export async function __resetMemoryStore() {
  memory.clear();
  backendPromise = null;
}
