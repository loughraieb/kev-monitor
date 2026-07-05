//! VirusTotal reputation for the unknown/untrusted tail. Feature-gated (`reputation`) and
//! deliberately lightweight: a dedicated **blocking** worker thread (no async runtime) that
//! pulls hashes off a channel, throttles to the free-tier limits, queries VT by hash, and
//! writes results into `reputation_cache`. The monitor reads that cache each tick — the worker
//! is fully detached so the UI never blocks on the network.
//!
//! Privacy: only the file's SHA-256 is sent to VirusTotal — never the file.

#[cfg(feature = "reputation")]
pub use worker::spawn_vt_worker;

#[cfg(feature = "reputation")]
mod worker {
    use std::collections::HashSet;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;
    use std::time::{Duration, Instant};

    use rusqlite::Connection;

    use crate::store::queries::{self, Reputation};

    // Free tier ≈ 4 req/min, 500/day. Stay comfortably under both.
    const MIN_INTERVAL: Duration = Duration::from_secs(16);
    const DAILY_CAP: u32 = 450;
    const TTL_CLEAN: i64 = 14 * 24 * 3600;
    const TTL_MALICIOUS: i64 = 90 * 24 * 3600;
    const TTL_UNKNOWN: i64 = 24 * 3600;

    /// Spawn the VT worker. Returns a channel; send SHA-256 hashes to look up.
    pub fn spawn_vt_worker(db_path: String, api_key: String) -> Sender<String> {
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || run(db_path, api_key, rx));
        tx
    }

    fn run(db_path: String, api_key: String, rx: Receiver<String>) {
        let conn = match Connection::open(&db_path) {
            Ok(c) => {
                let _ = c.pragma_update(None, "journal_mode", "WAL");
                let _ = c.busy_timeout(Duration::from_secs(5));
                c
            }
            Err(e) => {
                tracing::warn!(error = %e, "vt worker: cannot open db; disabling");
                return;
            }
        };

        let mut requested: HashSet<String> = HashSet::new();
        let mut last_req = Instant::now() - MIN_INTERVAL;
        let mut day = chrono::Utc::now().date_naive();
        let mut used_today: u32 = 0;

        tracing::info!("vt worker started");
        for sha in rx {
            // Dedup in-flight; skip if already cached fresh.
            if requested.contains(&sha) {
                continue;
            }
            if let Ok(Some(rep)) = queries::get_reputation(&conn, &sha) {
                if rep.is_fresh(chrono::Utc::now()) {
                    continue;
                }
            }

            // Daily cap (reset on UTC date change).
            let today = chrono::Utc::now().date_naive();
            if today != day {
                day = today;
                used_today = 0;
            }
            if used_today >= DAILY_CAP {
                continue;
            }

            // Throttle.
            let since = last_req.elapsed();
            if since < MIN_INTERVAL {
                thread::sleep(MIN_INTERVAL - since);
            }

            requested.insert(sha.clone());
            last_req = Instant::now();
            used_today += 1;

            let (detections, total, source, ttl) = match lookup(&api_key, &sha) {
                LookupResult::Found { detections, total } => {
                    let ttl = if detections > 0 { TTL_MALICIOUS } else { TTL_CLEAN };
                    (Some(detections), Some(total), "vt", ttl)
                }
                LookupResult::Unknown => (None, None, "vt-404", TTL_UNKNOWN),
                LookupResult::BadKey => {
                    tracing::warn!("vt worker: API key rejected (401); disabling");
                    return;
                }
                LookupResult::RateLimited => {
                    tracing::warn!("vt worker: rate limited (429); backing off");
                    requested.remove(&sha);
                    thread::sleep(Duration::from_secs(60));
                    continue;
                }
                LookupResult::Error => {
                    requested.remove(&sha);
                    continue;
                }
            };

            let rep = Reputation {
                sha256: sha.clone(),
                vt_detections: detections,
                vt_total: total,
                source: source.to_string(),
                fetched_at: chrono::Utc::now().to_rfc3339(),
                ttl_seconds: ttl,
            };
            if let Err(e) = queries::upsert_reputation(&conn, &rep) {
                tracing::warn!(error = %e, "vt worker: cache write failed");
            } else {
                tracing::debug!(sha = %sha, det = ?detections, total = ?total, "vt cached");
            }
        }
    }

    enum LookupResult {
        Found { detections: i64, total: i64 },
        Unknown,
        BadKey,
        RateLimited,
        Error,
    }

    /// Blocking VT v3 hash lookup. Sends only the hash.
    fn lookup(api_key: &str, sha256: &str) -> LookupResult {
        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let resp = ureq::get(&url)
            .set("x-apikey", api_key)
            .timeout(Duration::from_secs(20))
            .call();
        match resp {
            Ok(r) => {
                let body = match r.into_string() {
                    Ok(b) => b,
                    Err(_) => return LookupResult::Error,
                };
                let v: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(_) => return LookupResult::Error,
                };
                let st = &v["data"]["attributes"]["last_analysis_stats"];
                let get = |k: &str| st[k].as_i64().unwrap_or(0);
                let detections = get("malicious") + get("suspicious");
                let total =
                    detections + get("harmless") + get("undetected") + get("timeout") + get("failure");
                LookupResult::Found { detections, total }
            }
            Err(ureq::Error::Status(404, _)) => LookupResult::Unknown,
            Err(ureq::Error::Status(401, _)) => LookupResult::BadKey,
            Err(ureq::Error::Status(429, _)) => LookupResult::RateLimited,
            Err(_) => LookupResult::Error,
        }
    }
}
