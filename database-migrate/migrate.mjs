/* ------------------------------------------------------------------
   Database migrations — runner and generator
   ------------------------------------------------------------------
   Not published and not served: only site/ is. This is a command-line
   tool for the Plesk deployment, run from the repository root:

       npm run db -- --new "create vts_hub_store"   write a new migration
       npm run db -- --migration <uuid>             run that one migration
       npm run db -- --migration <uuid> --down      undo it
       npm run db -- --all                          run every pending one
       npm run db -- --status                       what is applied / pending
       npm run db -- --list                         migrations on disk only

   npm also accepts the flag on its own side of the `--`:

       npm run db --migration=<uuid>

   because npm turns `--migration=<uuid>` into npm_config_migration, and
   this file reads that too.

   Each migration is one file, database-migrate/migrations/
   migration-<uuid>.mjs, exporting `description`, `up(db)` and
   `down(db)`. `db` is a mysql2/promise pool for the VTS_DB_* database.
   Applied migrations are recorded in the `vts_hub_migrations` table so
   a migration is never run twice.

   Connection settings come from the same VTS_DB_* variables the
   application uses (lib/store-mariadb.js), read from the environment
   or from a .env file in the repository root. The runner fails loudly
   — a database it cannot reach is an error, never something to work
   around — which matches the store it is looking after.
   ------------------------------------------------------------------ */

import { readFile, writeFile, readdir } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const migrationsDir = path.join(here, "migrations");

export const MIGRATIONS_TABLE = "vts_hub_migrations";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FILE = /^migration-([0-9a-f-]{36})\.mjs$/i;

/* ---------------- environment ---------------- */

async function loadEnv() {
  try {
    const raw = await readFile(path.join(root, ".env"), "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (!match) continue;
      const value = match[2].trim().replace(/^["']|["']$/g, "");
      if (!(match[1] in process.env)) process.env[match[1]] = value;
    }
  } catch {
    /* no .env — the environment must carry the values */
  }
}

/* ---------------- arguments ---------------- */

/* Reads both `node migrate.mjs --migration <uuid>` and the values npm
   leaves in npm_config_* when the flag is given before `--`. */
function parseArgs(argv) {
  const opts = { new: null, migration: null, down: false, all: false, status: false, list: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const [flag, inline] = arg.includes("=") ? arg.split(/=(.*)/s) : [arg, undefined];
    const next = () => (inline !== undefined ? inline : argv[++i]);
    switch (flag) {
      case "--new": opts.new = next() || ""; break;
      case "--migration": case "-m": opts.migration = next(); break;
      case "--down": opts.down = true; break;
      case "--all": opts.all = true; break;
      case "--status": opts.status = true; break;
      case "--list": opts.list = true; break;
      case "--help": case "-h": opts.help = true; break;
      default:
        throw new Error("Unknown argument: " + arg);
    }
  }
  const npmc = (k) => process.env["npm_config_" + k];
  if (!opts.migration && npmc("migration") && npmc("migration") !== "true") opts.migration = npmc("migration");
  if (opts.new === null && npmc("new") !== undefined) opts.new = npmc("new") === "true" ? "" : npmc("new");
  if (npmc("down") === "true") opts.down = true;
  if (npmc("all") === "true") opts.all = true;
  if (npmc("status") === "true") opts.status = true;
  if (npmc("list") === "true") opts.list = true;
  return opts;
}

function usage() {
  console.log(`
  VTS Hub — database migrations

    npm run db -- --new "<description>"       write migrations/migration-<uuid>.mjs
    npm run db -- --migration <uuid>          apply one migration
    npm run db -- --migration <uuid> --down   roll one migration back
    npm run db -- --all                       apply every pending migration, oldest first
    npm run db -- --status                    show applied and pending migrations
    npm run db -- --list                      list migration files (no database needed)

  Connection: VTS_DB_HOST, VTS_DB_PORT, VTS_DB_NAME, VTS_DB_USER, VTS_DB_PASSWORD
  (from the environment or a .env file in the repository root).
`);
}

/* ---------------- migration files ---------------- */

async function listMigrations() {
  let names = [];
  try {
    names = await readdir(migrationsDir);
  } catch {
    return [];
  }
  const found = [];
  for (const name of names) {
    const match = FILE.exec(name);
    if (!match) continue;
    const mod = await import(pathToFileURL(path.join(migrationsDir, name)).href);
    if (typeof mod.up !== "function" || typeof mod.down !== "function") {
      throw new Error(name + " must export up(db) and down(db)");
    }
    found.push({
      id: match[1].toLowerCase(),
      file: name,
      createdAt: mod.createdAt || null,
      description: mod.description || "",
      up: mod.up,
      down: mod.down,
    });
  }
  /* Oldest first, by the timestamp each file records at generation. */
  return found.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
}

function slug(text) {
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
}

export async function generateMigration(description) {
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const name = "migration-" + id + ".mjs";
  const file = path.join(migrationsDir, name);

  const source = `/* ------------------------------------------------------------------
   Migration ${id}
   ------------------------------------------------------------------
   ${description || "(describe what this migration changes)"}

   Generated ${createdAt} by database-migrate/migrate.mjs.
   Run with:   npm run db -- --migration ${id}
   Undo with:  npm run db -- --migration ${id} --down

   \`db\` is a mysql2/promise pool connected to the VTS_DB_* database.
   Write the structure with parameterised statements and make \`up\`
   safe to run against a database that already has part of it
   (CREATE TABLE IF NOT EXISTS, checks against information_schema).
   ------------------------------------------------------------------ */

export const id = "${id}";
export const createdAt = "${createdAt}";
export const description = ${JSON.stringify(description || "")};

export async function up(db) {
  // await db.query("CREATE TABLE IF NOT EXISTS example (...)");
}

export async function down(db) {
  // await db.query("DROP TABLE IF EXISTS example");
}
`;
  await writeFile(file, source, { flag: "wx" });
  return { id, file, name, slug: slug(description) };
}

/* ---------------- database ---------------- */

function dbSettings() {
  const settings = {
    host: process.env.VTS_DB_HOST || "localhost",
    port: Number(process.env.VTS_DB_PORT || "3306"),
    database: process.env.VTS_DB_NAME,
    user: process.env.VTS_DB_USER,
    password: process.env.VTS_DB_PASSWORD || "",
  };
  const missing = ["database", "user"].filter((k) => !settings[k]);
  if (missing.length) {
    throw new Error("VTS_DB_NAME and VTS_DB_USER must be set (environment or .env)");
  }
  return settings;
}

async function openPool() {
  const { createPool } = await import("mysql2/promise");
  const settings = dbSettings();
  const pool = createPool({
    ...settings,
    waitForConnections: true,
    connectionLimit: 2,
    charset: "utf8mb4",
    connectTimeout: 5000,
    multipleStatements: false,
  });
  await pool.query("SELECT 1");
  await pool.query(
    "CREATE TABLE IF NOT EXISTS " + MIGRATIONS_TABLE + " (" +
      "  id          CHAR(36)     NOT NULL PRIMARY KEY," +
      "  description VARCHAR(255) NOT NULL DEFAULT ''," +
      "  applied_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)" +
      ") ENGINE=InnoDB CHARACTER SET utf8mb4"
  );
  return { pool, settings };
}

async function appliedIds(pool) {
  const [rows] = await pool.query("SELECT id, applied_at FROM " + MIGRATIONS_TABLE);
  return new Map(rows.map((r) => [String(r.id).toLowerCase(), r.applied_at]));
}

async function applyOne(pool, migration, direction) {
  const applied = await appliedIds(pool);
  const done = applied.has(migration.id);

  if (direction === "up") {
    if (done) {
      console.log("  skip   " + migration.id + " already applied " + fmt(applied.get(migration.id)));
      return false;
    }
    console.log("  up     " + migration.id + "  " + migration.description);
    await migration.up(pool);
    await pool.execute(
      "INSERT INTO " + MIGRATIONS_TABLE + " (id, description) VALUES (?, ?)",
      [migration.id, migration.description.slice(0, 255)]
    );
    return true;
  }

  if (!done) {
    console.log("  skip   " + migration.id + " is not applied; nothing to undo");
    return false;
  }
  console.log("  down   " + migration.id + "  " + migration.description);
  await migration.down(pool);
  await pool.execute("DELETE FROM " + MIGRATIONS_TABLE + " WHERE id = ?", [migration.id]);
  return true;
}

const fmt = (d) => (d instanceof Date ? d.toISOString() : String(d ?? ""));

/* ---------------- commands ---------------- */

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) return usage();

  if (opts.new !== null) {
    const made = await generateMigration(opts.new);
    console.log("");
    console.log("  created  database-migrate/migrations/" + made.name);
    console.log("  run      npm run db -- --migration " + made.id);
    console.log("");
    return;
  }

  const migrations = await listMigrations();

  if (opts.list) {
    console.log("");
    for (const m of migrations) console.log("  " + m.id + "  " + fmt(m.createdAt) + "  " + m.description);
    if (!migrations.length) console.log("  (no migrations on disk)");
    console.log("");
    return;
  }

  if (!opts.migration && !opts.all && !opts.status) {
    usage();
    throw new Error("Nothing to do: give --migration <uuid>, --all, --status, --list or --new.");
  }

  /* Validate before touching the database, so a typo is reported as a
     typo rather than as a connection attempt. */
  let target = null;
  if (opts.migration) {
    const id = String(opts.migration).toLowerCase();
    if (!UUID.test(id)) throw new Error("--migration expects a UUID, got: " + opts.migration);
    target = migrations.find((m) => m.id === id);
    if (!target) throw new Error("No file database-migrate/migrations/migration-" + id + ".mjs");
  }
  if (opts.all && opts.down) {
    throw new Error("--all cannot be combined with --down; roll back one migration at a time.");
  }

  await loadEnv();
  const { pool, settings } = await openPool();
  console.log("");
  console.log("  database " + settings.user + "@" + settings.host + ":" + settings.port + "/" + settings.database);

  try {
    if (opts.status) {
      const applied = await appliedIds(pool);
      for (const m of migrations) {
        const when = applied.get(m.id);
        console.log("  " + (when ? "applied " + fmt(when) : "pending                 ") + "  " + m.id + "  " + m.description);
      }
      for (const [id, when] of applied) {
        if (!migrations.some((m) => m.id === id)) {
          console.log("  applied " + fmt(when) + "  " + id + "  (file missing from disk)");
        }
      }
      if (!migrations.length) console.log("  (no migrations on disk)");
      console.log("");
      return;
    }

    if (opts.all) {
      let n = 0;
      for (const m of migrations) if (await applyOne(pool, m, "up")) n++;
      console.log("  done   " + n + " migration" + (n === 1 ? "" : "s") + " applied");
      console.log("");
      return;
    }

    await applyOne(pool, target, opts.down ? "down" : "up");
    console.log("");
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("");
  console.error("  FATAL  " + (err && err.message ? err.message : String(err)));
  console.error("");
  process.exit(1);
});
