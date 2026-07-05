//! Phase 4 — table DDL and migration.
//!
//! Three tables: `known_binaries` (the trusted baseline), `reputation_cache` (Phase 8
//! VirusTotal results with TTL), and `observations` (Phase 9 scan history). `expected_paths`
//! and `expected_parents` are stored as JSON arrays of strings.

use rusqlite::Connection;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS known_binaries (
    sha256             TEXT PRIMARY KEY,
    expected_name      TEXT,
    expected_publisher TEXT,
    expected_paths     TEXT NOT NULL DEFAULT '[]',   -- json array
    expected_parents   TEXT NOT NULL DEFAULT '[]',   -- json array
    verdict            TEXT NOT NULL DEFAULT 'trusted',
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reputation_cache (
    sha256        TEXT PRIMARY KEY,
    vt_detections INTEGER,
    vt_total      INTEGER,
    source        TEXT,
    fetched_at    TEXT NOT NULL,
    ttl_seconds   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT,
    sha256       TEXT,
    name         TEXT,
    image_path   TEXT,
    ppid_name    TEXT,
    verdict      TEXT,
    score        INTEGER,
    collected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_observations_sha256 ON observations(sha256);
CREATE INDEX IF NOT EXISTS idx_known_name ON known_binaries(expected_name);
"#;

/// Create tables/indexes if they don't exist. Idempotent.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(DDL)
}
