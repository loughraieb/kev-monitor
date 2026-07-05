//! Phase 4 — local SQLite store (baseline, reputation cache, observations).

pub mod queries;
pub mod schema;

use anyhow::Context;
use rusqlite::Connection;

/// Open (creating if needed) the SQLite store at `path` and run migrations.
pub struct Store {
    pub conn: Connection,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("opening sqlite store at {path}"))?;
        schema::migrate(&conn).context("running migrations")?;
        Ok(Self { conn })
    }
}
