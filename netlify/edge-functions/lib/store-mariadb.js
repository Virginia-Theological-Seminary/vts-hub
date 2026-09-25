/* ------------------------------------------------------------------
   MariaDB backend for the user store (TEMPORARY DEVELOPMENT AUTH)
   ------------------------------------------------------------------
   The persistent store for the Plesk deployment. Selected with
   VTS_AUTH_STORE=mariadb and configured with VTS_DB_HOST / PORT / NAME /
   USER / PASSWORD.

   One table, key -> JSON record, the same shape the memory and Blobs
   backends hold. That keeps every caller in user-store.js unchanged —
   createUser, updateUser, findUserByEmail, putToken, takeToken all
   work on the same get/insert/set/delete interface — and it is still
   easy to inspect from the Plesk database panel:

       SELECT k, kind, JSON_VALUE(v, '$.email') AS email,
              JSON_VALUE(v, '$.emailVerifiedAt') AS verified_at,
              updated_at
       FROM vts_hub_store WHERE kind = 'user';

   Records hold the password HASH only (see password.js); nothing in
   this table can be used to sign in.

   Fails loudly. If the database cannot be reached, the store throws
   and the application refuses to serve sign-in — it never falls back
   to memory. A store that silently forgets accounts is worse than one
   that is plainly down (that is Bug 1).

   The driver is imported by a non-literal specifier so the Netlify
   edge bundler (kept as a fallback host) leaves it alone: on Netlify
   VTS_AUTH_STORE is unset, Blobs is used, and this module never runs.
   ------------------------------------------------------------------ */

import { env } from "./runtime.js";

export const TABLE = "vts_hub_store";

export function mariadbSettings() {
  return {
    host: env("VTS_DB_HOST", "localhost"),
    port: Number(env("VTS_DB_PORT", "3306")),
    database: env("VTS_DB_NAME"),
    user: env("VTS_DB_USER"),
    password: env("VTS_DB_PASSWORD", ""),
  };
}

function kindOf(key) {
  return String(key).startsWith("token:") ? "token" : "user";
}

/* Opens a pool, ensures the table exists, proves the connection works.
   Any failure is thrown to the caller. */
export async function mariadbBackend() {
  const settings = mariadbSettings();
  for (const name of ["database", "user"]) {
    if (!settings[name]) {
      throw new Error(
        "VTS_AUTH_STORE=mariadb but VTS_DB_NAME / VTS_DB_USER are not set"
      );
    }
  }

  const driver = "mysql2/promise";
  const { createPool } = await import(driver);

  const pool = createPool({
    ...settings,
    waitForConnections: true,
    connectionLimit: 5,
    charset: "utf8mb4",
    connectTimeout: 5000,
  });

  await pool.query(
    "CREATE TABLE IF NOT EXISTS " + TABLE + " (" +
      "  k          VARCHAR(64)  NOT NULL PRIMARY KEY," +
      "  kind       VARCHAR(16)  NOT NULL," +
      "  v          LONGTEXT     NOT NULL," +
      "  created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)," +
      "  updated_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)," +
      "  INDEX idx_kind (kind)" +
      ") ENGINE=InnoDB CHARACTER SET utf8mb4"
  );
  await pool.query("SELECT 1");

  return {
    kind: "mariadb",

    async get(key) {
      const [rows] = await pool.execute("SELECT v FROM " + TABLE + " WHERE k = ?", [key]);
      if (!rows.length) return null;
      try {
        return JSON.parse(rows[0].v);
      } catch {
        return null;
      }
    },

    /* Create-only. Returns false if the key already exists, so two
       simultaneous sign-ups for one address cannot both succeed —
       the database's primary key is the arbiter, not a read-then-write. */
    async insert(key, value) {
      try {
        await pool.execute(
          "INSERT INTO " + TABLE + " (k, kind, v) VALUES (?, ?, ?)",
          [key, kindOf(key), JSON.stringify(value)]
        );
        return true;
      } catch (err) {
        if (err && err.code === "ER_DUP_ENTRY") return false;
        throw err;
      }
    },

    async set(key, value) {
      await pool.execute(
        "INSERT INTO " + TABLE + " (k, kind, v) VALUES (?, ?, ?) " +
          "ON DUPLICATE KEY UPDATE v = VALUES(v)",
        [key, kindOf(key), JSON.stringify(value)]
      );
    },

    async delete(key) {
      await pool.execute("DELETE FROM " + TABLE + " WHERE k = ?", [key]);
    },

    async count() {
      const [rows] = await pool.query(
        "SELECT COUNT(*) AS n FROM " + TABLE + " WHERE kind = 'user'"
      );
      return Number(rows[0].n);
    },

    async close() {
      await pool.end();
    },
  };
}
