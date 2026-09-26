#!/usr/bin/env node
/**
 * Apply db/migrations/001_init.sql to the database in DATABASE_URL.
 * Usage: DATABASE_URL=postgres://... node scripts/db-init.mjs
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";

const { Client } = pg;
const url = process.env.DATABASE_URL;
if (!url) {
  console.error("ERROR: DATABASE_URL is not set.");
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
const migrations = readdirSync(join(here, "..", "db", "migrations"))
  .filter((f) => f.endsWith(".sql"))
  .sort();

const client = new Client({ connectionString: url });
try {
  await client.connect();
  for (const file of migrations) {
    const sql = readFileSync(join(here, "..", "db", "migrations", file), "utf8");
    await client.query(sql);
    console.log(`Applied ${file}`);
  }
  console.log("Kryptos schema applied successfully.");
} catch (err) {
  console.error("Migration failed:", err.message);
  process.exit(1);
} finally {
  await client.end().catch(() => undefined);
}
