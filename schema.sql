-- Run this once against the D1 database bound as "DB" in wrangler.toml.
-- Dashboard: Storage & databases > D1 > your database > Console.
-- CLI alternative: wrangler d1 execute <name> --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS routers (
  device_id    TEXT PRIMARY KEY,
  secret_hash  TEXT NOT NULL,   -- SHA-256 hex of the router's secret; plaintext is never stored
  label        TEXT,             -- free-form, e.g. "Home router" - for your own reference only
  created_at   TEXT NOT NULL,
  disabled_at  TEXT,             -- NULL = active; non-NULL = revoked
  last_seen_at TEXT              -- bumped on every successful /presign call
);
