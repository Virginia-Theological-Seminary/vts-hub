/* ------------------------------------------------------------------
   Migration 1a88af9c-8dd0-4614-b385-493775e962bd
   ------------------------------------------------------------------
   Create the account store: the vts_hub_store table that
   netlify/edge-functions/lib/store-mariadb.js reads and writes.

   One row per key holding a JSON record — an account (password HASH
   only, names, role, emailVerifiedAt, passwordChangedAt, timestamps) or
   a one-time token keyed by its hash. `kind` is 'user' or 'token' so
   the Plesk database panel can filter without parsing JSON.

   Generated 2026-09-23 by database-migrate/migrate.mjs.
   Run with:   npm run db -- --migration 1a88af9c-8dd0-4614-b385-493775e962bd
   Undo with:  npm run db -- --migration 1a88af9c-8dd0-4614-b385-493775e962bd --down

   The structure is built programmatically from a description of the
   columns and indexes, and `up` checks information_schema first so it
   is safe against a database where store-mariadb.js already created
   the table on first start: existing columns and indexes are kept,
   missing ones are added, and no row is touched.
   ------------------------------------------------------------------ */

import { TABLE } from "../../netlify/edge-functions/lib/store-mariadb.js";

export const id = "1a88af9c-8dd0-4614-b385-493775e962bd";
export const createdAt = "2026-09-23T18:30:00.000Z";
export const description = "create vts_hub_store (accounts and one-time tokens)";

/* The structure, as data. Column order is creation order. */
const columns = [
  { name: "k",          ddl: "VARCHAR(64) NOT NULL" },
  { name: "kind",       ddl: "VARCHAR(16) NOT NULL" },
  { name: "v",          ddl: "LONGTEXT NOT NULL" },
  { name: "created_at", ddl: "DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)" },
  { name: "updated_at", ddl: "DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)" },
];
const primaryKey = ["k"];
const indexes = [{ name: "idx_kind", columns: ["kind"] }];

/* Identifiers come from the lists above, never from input, so they are
   safe to interpolate; every value is bound with a placeholder. */
const q = (ident) => "`" + String(ident).replace(/`/g, "``") + "`";

async function tableExists(db) {
  const [rows] = await db.execute(
    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
    [TABLE]
  );
  return rows.length > 0;
}

async function existingColumns(db) {
  const [rows] = await db.execute(
    "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
    [TABLE]
  );
  return new Set(rows.map((r) => r.COLUMN_NAME));
}

async function existingIndexes(db) {
  const [rows] = await db.execute(
    "SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
    [TABLE]
  );
  return new Set(rows.map((r) => r.INDEX_NAME));
}

export async function up(db) {
  if (!(await tableExists(db))) {
    const parts = columns.map((c) => q(c.name) + " " + c.ddl);
    parts.push("PRIMARY KEY (" + primaryKey.map(q).join(", ") + ")");
    for (const ix of indexes) parts.push("INDEX " + q(ix.name) + " (" + ix.columns.map(q).join(", ") + ")");
    await db.query("CREATE TABLE " + q(TABLE) + " (" + parts.join(", ") + ") ENGINE=InnoDB CHARACTER SET utf8mb4");
    return;
  }

  /* The table is already there (store-mariadb.js creates it on first
     start). Bring it up to this structure without dropping anything. */
  const have = await existingColumns(db);
  let after = null;
  for (const c of columns) {
    if (!have.has(c.name)) {
      await db.query(
        "ALTER TABLE " + q(TABLE) + " ADD COLUMN " + q(c.name) + " " + c.ddl +
          (after ? " AFTER " + q(after) : " FIRST")
      );
    }
    after = c.name;
  }

  const ixs = await existingIndexes(db);
  if (!ixs.has("PRIMARY")) {
    await db.query("ALTER TABLE " + q(TABLE) + " ADD PRIMARY KEY (" + primaryKey.map(q).join(", ") + ")");
  }
  for (const ix of indexes) {
    if (!ixs.has(ix.name)) {
      await db.query("ALTER TABLE " + q(TABLE) + " ADD INDEX " + q(ix.name) + " (" + ix.columns.map(q).join(", ") + ")");
    }
  }
}

/* Drops the accounts. Every development account and pending link goes
   with it; people sign up again. This is the intended end state once
   AUTH_MODE=entra, and otherwise something to do on purpose. */
export async function down(db) {
  await db.query("DROP TABLE IF EXISTS " + q(TABLE));
}
