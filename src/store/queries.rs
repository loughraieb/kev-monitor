//! Phase 4 — CRUD over the store. The baseline upsert is idempotent: re-running on the
//! same machine updates `last_seen` and merges any newly-seen path/parent without creating
//! duplicates.

use anyhow::Context;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// A trusted-baseline entry. `expected_paths`/`expected_parents` accumulate every distinct
/// location/parent under which this exact image (by sha256) has been observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownBinary {
    pub sha256: String,
    pub expected_name: Option<String>,
    pub expected_publisher: Option<String>,
    pub expected_paths: Vec<String>,
    pub expected_parents: Vec<String>,
    pub verdict: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Whether an upsert created a new row or updated an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertKind {
    Inserted,
    Updated,
}

fn to_json(v: &[String]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string())
}

fn from_json(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

/// Look up a baseline entry by hash.
pub fn get_known(conn: &Connection, sha256: &str) -> anyhow::Result<Option<KnownBinary>> {
    let row = conn
        .query_row(
            "SELECT sha256, expected_name, expected_publisher, expected_paths, \
             expected_parents, verdict, first_seen, last_seen \
             FROM known_binaries WHERE sha256 = ?1",
            params![sha256],
            |r| {
                Ok(KnownBinary {
                    sha256: r.get(0)?,
                    expected_name: r.get(1)?,
                    expected_publisher: r.get(2)?,
                    expected_paths: from_json(&r.get::<_, String>(3)?),
                    expected_parents: from_json(&r.get::<_, String>(4)?),
                    verdict: r.get(5)?,
                    first_seen: r.get(6)?,
                    last_seen: r.get(7)?,
                })
            },
        )
        .optional()
        .context("querying known_binaries")?;
    Ok(row)
}

/// Insert or update a trusted baseline entry from one observed process image.
pub fn upsert_baseline(
    conn: &Connection,
    sha256: &str,
    name: &str,
    publisher: Option<&str>,
    image_path: &str,
    parent_name: Option<&str>,
    now: &str,
) -> anyhow::Result<UpsertKind> {
    match get_known(conn, sha256)? {
        Some(mut kb) => {
            if !kb.expected_paths.iter().any(|p| p.eq_ignore_ascii_case(image_path)) {
                kb.expected_paths.push(image_path.to_string());
            }
            if let Some(parent) = parent_name {
                if !kb.expected_parents.iter().any(|p| p.eq_ignore_ascii_case(parent)) {
                    kb.expected_parents.push(parent.to_string());
                }
            }
            conn.execute(
                "UPDATE known_binaries \
                 SET expected_paths = ?2, expected_parents = ?3, last_seen = ?4 \
                 WHERE sha256 = ?1",
                params![sha256, to_json(&kb.expected_paths), to_json(&kb.expected_parents), now],
            )
            .context("updating known_binaries")?;
            Ok(UpsertKind::Updated)
        }
        None => {
            let paths = vec![image_path.to_string()];
            let parents: Vec<String> =
                parent_name.map(|p| vec![p.to_string()]).unwrap_or_default();
            conn.execute(
                "INSERT INTO known_binaries \
                 (sha256, expected_name, expected_publisher, expected_paths, expected_parents, \
                  verdict, first_seen, last_seen) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'trusted', ?6, ?6)",
                params![sha256, name, publisher, to_json(&paths), to_json(&parents), now],
            )
            .context("inserting known_binaries")?;
            Ok(UpsertKind::Inserted)
        }
    }
}

/// Count baseline entries.
pub fn count_known(conn: &Connection) -> anyhow::Result<i64> {
    let n = conn
        .query_row("SELECT COUNT(*) FROM known_binaries", [], |r| r.get(0))
        .context("counting known_binaries")?;
    Ok(n)
}

/// A cached VirusTotal (or other source) reputation result for one file hash.
#[derive(Debug, Clone)]
pub struct Reputation {
    pub sha256: String,
    /// Engines flagging the file (malicious + suspicious). `None` = unknown to the source.
    pub vt_detections: Option<i64>,
    pub vt_total: Option<i64>,
    pub source: String,
    pub fetched_at: String, // RFC3339
    pub ttl_seconds: i64,
}

impl Reputation {
    /// Whether this cache entry is still within its TTL at `now`.
    pub fn is_fresh(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        match chrono::DateTime::parse_from_rfc3339(&self.fetched_at) {
            Ok(t) => now < t.with_timezone(&chrono::Utc) + chrono::Duration::seconds(self.ttl_seconds),
            Err(_) => false,
        }
    }
}

/// Look up a cached reputation by hash.
pub fn get_reputation(conn: &Connection, sha256: &str) -> anyhow::Result<Option<Reputation>> {
    let row = conn
        .query_row(
            "SELECT sha256, vt_detections, vt_total, source, fetched_at, ttl_seconds \
             FROM reputation_cache WHERE sha256 = ?1",
            params![sha256],
            |r| {
                Ok(Reputation {
                    sha256: r.get(0)?,
                    vt_detections: r.get(1)?,
                    vt_total: r.get(2)?,
                    source: r.get(3)?,
                    fetched_at: r.get(4)?,
                    ttl_seconds: r.get(5)?,
                })
            },
        )
        .optional()
        .context("querying reputation_cache")?;
    Ok(row)
}

/// Insert or replace a reputation entry.
pub fn upsert_reputation(conn: &Connection, rep: &Reputation) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO reputation_cache \
         (sha256, vt_detections, vt_total, source, fetched_at, ttl_seconds) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            rep.sha256,
            rep.vt_detections,
            rep.vt_total,
            rep.source,
            rep.fetched_at,
            rep.ttl_seconds
        ],
    )
    .context("upserting reputation_cache")?;
    Ok(())
}

/// Append a scan observation (used by Phase 9 `watch`).
#[allow(clippy::too_many_arguments)]
pub fn insert_observation(
    conn: &Connection,
    host: Option<&str>,
    sha256: Option<&str>,
    name: &str,
    image_path: Option<&str>,
    ppid_name: Option<&str>,
    verdict: Option<&str>,
    score: Option<i32>,
    collected_at: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO observations \
         (host, sha256, name, image_path, ppid_name, verdict, score, collected_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![host, sha256, name, image_path, ppid_name, verdict, score, collected_at],
    )
    .context("inserting observation")?;
    Ok(())
}
