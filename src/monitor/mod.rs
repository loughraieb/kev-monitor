//! Live process monitor — the shared engine behind the TUI (and, later, the Tauri/web
//! frontends). It keeps a `sysinfo::System` across ticks so CPU% deltas work, samples cheap
//! resource stats every tick, and **caches each process's verdict** (verify once on first
//! sight) so the expensive hash + Authenticode work isn't repeated every refresh.

pub mod tui;

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde::Serialize;
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Pid, ProcessRefreshKind, RefreshKind, System, UpdateKind,
    Users,
};

use crate::collector::{hash, signature};
use crate::config::Config;
use crate::engine::score;
use crate::model::{NetworkConn, ProcessRecord, Signature, Verdict};
use crate::store::{queries, Store};

/// A process as shown in the live monitor.
#[derive(Debug, Clone, Serialize)]
pub struct LiveProcess {
    pub pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub parent_name: Option<String>,
    pub user: Option<String>,
    /// Best-guess identity ("what it looks like") from the knowledge base.
    pub description: Option<String>,
    /// Authenticode signing publisher, when validly signed.
    pub publisher: Option<String>,
    /// SHA-256 of the image (computed for the untrusted tail), surfaced for investigation.
    pub sha256: Option<String>,
    /// Live TCP connections owned by this process (sampled each tick, not cached).
    pub network: Vec<NetworkConn>,
    /// VirusTotal detections / total engines, when a cached result exists.
    pub vt_detections: Option<i64>,
    pub vt_total: Option<i64>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub signed: Option<bool>,
    /// `None` while the (expensive) verification for this process is still pending.
    pub verdict: Option<Verdict>,
    pub score: i32,
    pub fired_rules: Vec<String>,
}

/// Machine-wide resource stats for the header.
#[derive(Debug, Clone, Serialize)]
pub struct GlobalStats {
    pub cpu_percent: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub process_count: usize,
}

/// One refresh of the monitor.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub processes: Vec<LiveProcess>,
    pub global: GlobalStats,
    /// How many processes still await verification (verdict not yet computed).
    pub pending: usize,
}

/// Raw per-process data gathered from `sysinfo` before verdict resolution.
struct RawProc {
    pid: u32,
    name: String,
    image_path: Option<String>,
    parent_name: Option<String>,
    user: Option<String>,
    cpu_percent: f32,
    memory_bytes: u64,
}

/// Cached verdict for a (pid, image_path) — valid for the lifetime of that process.
#[derive(Clone)]
struct CachedVerdict {
    signed: Option<bool>,
    publisher: Option<String>,
    description: Option<String>,
    /// SHA-256 (only computed for the untrusted tail) — used for reputation lookups.
    sha256: Option<String>,
    verdict: Verdict,
    score: i32,
    fired_rules: Vec<String>,
}

pub struct Monitor {
    sys: System,
    users: Users,
    config: Config,
    store: Option<Store>,
    cache: HashMap<(u32, String), CachedVerdict>,
    /// Channel to the VirusTotal worker (untrusted-tail hashes). `None` if disabled/no key.
    rep_tx: Option<std::sync::mpsc::Sender<String>>,
    /// Hashes already sent to the VT worker this session (avoid re-queuing every tick).
    rep_requested: std::collections::HashSet<String>,
}

impl Monitor {
    pub fn new(config: Config) -> Self {
        let store = if Path::new(&config.store.db_path).exists() {
            match Store::open(&config.store.db_path) {
                Ok(s) => {
                    tracing::info!(db = %config.store.db_path, "monitor: baseline store opened");
                    Some(s)
                }
                Err(e) => {
                    tracing::warn!(db = %config.store.db_path, error = %e, "monitor: could not open baseline store");
                    None
                }
            }
        } else {
            tracing::info!(db = %config.store.db_path, "monitor: no baseline store (run `kev baseline`); everything will be Unknown/Suspicious");
            None
        };
        tracing::info!(
            online_revocation = config.signature.online_revocation,
            "monitor initialized"
        );

        // VirusTotal worker (only with the feature + a store + enabled + a key).
        let rep_tx = Self::spawn_reputation(&config, store.is_some());

        Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
            config,
            store,
            cache: HashMap::new(),
            rep_tx,
            rep_requested: std::collections::HashSet::new(),
        }
    }

    #[cfg(feature = "reputation")]
    fn spawn_reputation(config: &Config, has_store: bool) -> Option<std::sync::mpsc::Sender<String>> {
        if !config.reputation.enabled || !has_store {
            return None;
        }
        let key = std::env::var("VT_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .or_else(|| config.reputation.api_key.clone())?;
        tracing::info!("reputation: VirusTotal worker enabled");
        Some(crate::reputation::spawn_vt_worker(config.store.db_path.clone(), key))
    }

    #[cfg(not(feature = "reputation"))]
    fn spawn_reputation(_config: &Config, _has_store: bool) -> Option<std::sync::mpsc::Sender<String>> {
        None
    }

    fn refresh_kind() -> RefreshKind {
        let procs = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet);
        RefreshKind::nothing()
            .with_processes(procs)
            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
            .with_memory(MemoryRefreshKind::nothing().with_ram())
    }

    /// Refresh stats and produce a snapshot. CPU% is meaningful from the second tick on.
    ///
    /// `verify_budget` caps how many *not-yet-cached* processes are verified this tick
    /// (verification = hash + signature, which is slow). Uncapped work would block the first
    /// snapshot until every process is verified; budgeting lets the table + resources appear
    /// immediately while verdicts fill in over subsequent ticks. Use `usize::MAX` to verify
    /// everything in one call.
    pub fn tick(&mut self, verify_budget: usize) -> Snapshot {
        let t0 = Instant::now();
        self.sys.refresh_specifics(Self::refresh_kind());
        // Live TCP connections per pid (one syscall; not cached — connections change).
        let conns = crate::collector::network::connections_by_pid();

        // Pass 1: gather raw per-process data while `sys` is borrowed.
        let raws: Vec<RawProc> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, proc_)| RawProc {
                pid: pid.as_u32(),
                name: proc_.name().to_string_lossy().into_owned(),
                image_path: proc_.exe().map(|p| p.to_string_lossy().into_owned()),
                parent_name: proc_
                    .parent()
                    .and_then(|pp| self.sys.process(pp))
                    .map(|pp| pp.name().to_string_lossy().into_owned()),
                user: proc_
                    .user_id()
                    .and_then(|uid| self.users.get_user_by_id(uid))
                    .map(|u| u.name().to_string()),
                cpu_percent: proc_.cpu_usage(),
                memory_bytes: proc_.memory(),
            })
            .collect();

        let global = GlobalStats {
            cpu_percent: self.sys.global_cpu_usage(),
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            process_count: raws.len(),
        };

        // Pass 2: resolve each verdict from cache, verifying up to `verify_budget` new ones.
        let mut processes = Vec::with_capacity(raws.len());
        let mut alive: std::collections::HashSet<(u32, String)> =
            std::collections::HashSet::with_capacity(raws.len());
        let mut budget_left = verify_budget;
        let mut pending = 0usize;
        let mut verified = 0usize;
        for r in raws {
            let key = (r.pid, r.image_path.clone().unwrap_or_default());
            alive.insert(key.clone());

            let resolved = match self.cache.get(&key).cloned() {
                Some(c) => Some(c),
                None if budget_left > 0 => {
                    let cv =
                        self.verify(r.pid, &r.name, r.image_path.as_deref(), r.parent_name.as_deref());
                    self.cache.insert(key, cv.clone());
                    budget_left -= 1;
                    verified += 1;
                    Some(cv)
                }
                None => {
                    pending += 1;
                    None
                }
            };

            let (mut verdict, score, fired_rules, signed, description, publisher, sha256) =
                match resolved {
                    Some(c) => (
                        Some(c.verdict),
                        c.score,
                        c.fired_rules,
                        c.signed,
                        c.description,
                        c.publisher,
                        c.sha256,
                    ),
                    None => (None, 0, Vec::new(), None, None, None, None),
                };

            // VirusTotal reputation for the untrusted tail — a cheap cache read each tick; the
            // detached worker fills/refreshes the cache. Trusted processes are never queried.
            let (mut vt_detections, mut vt_total) = (None, None);
            let is_tail = matches!(
                verdict,
                Some(Verdict::UnknownSigned) | Some(Verdict::Suspicious) | Some(Verdict::Malicious)
            );
            if is_tail {
                if let (Some(store), Some(sha)) = (self.store.as_ref(), sha256.as_deref()) {
                    let rep = queries::get_reputation(&store.conn, sha).ok().flatten();
                    let mut need_lookup = rep.is_none();
                    if let Some(rep) = &rep {
                        vt_detections = rep.vt_detections;
                        vt_total = rep.vt_total;
                        if let Some(d) = rep.vt_detections {
                            if d >= self.config.reputation.vt_malicious_threshold {
                                verdict = Some(Verdict::Malicious);
                            } else if d >= 1 && verdict == Some(Verdict::UnknownSigned) {
                                verdict = Some(Verdict::Suspicious);
                            }
                        }
                        need_lookup = !rep.is_fresh(chrono::Utc::now());
                    }
                    if need_lookup && self.rep_requested.insert(sha.to_string()) {
                        if let Some(tx) = &self.rep_tx {
                            let _ = tx.send(sha.to_string());
                        }
                    }
                }
            }

            processes.push(LiveProcess {
                pid: r.pid,
                name: r.name,
                image_path: r.image_path,
                parent_name: r.parent_name,
                user: r.user,
                description,
                publisher,
                sha256,
                network: conns.get(&r.pid).cloned().unwrap_or_default(),
                vt_detections,
                vt_total,
                cpu_percent: r.cpu_percent,
                memory_bytes: r.memory_bytes,
                signed,
                verdict,
                score,
                fired_rules,
            });
        }

        // Evict cache entries for processes that have exited.
        self.cache.retain(|k, _| alive.contains(k));

        tracing::info!(
            procs = processes.len(),
            verified,
            pending,
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "monitor tick"
        );
        Snapshot { processes, global, pending }
    }

    /// Expensive path: hash + verify signature + score. Called once per (pid, path).
    fn verify(
        &self,
        pid: u32,
        name: &str,
        image_path: Option<&str>,
        parent_name: Option<&str>,
    ) -> CachedVerdict {
        let start = Instant::now();

        // Signature first — it's cheaper than hashing a large binary and yields the publisher
        // we trust on.
        let sig_start = Instant::now();
        let signature: Option<Signature> = image_path.map(|p| {
            signature::verify_file(p, self.config.signature.online_revocation).into()
        });
        let sig_ms = sig_start.elapsed().as_millis() as u64;
        let signed = signature.as_ref().map(|s| s.signed);
        let publisher = signature.as_ref().and_then(|s| s.publisher.clone());
        let trusted_pub = signature.as_ref().is_some_and(|s| {
            s.signed
                && s.chain_valid
                && !s.revoked
                && s.publisher.as_deref().is_some_and(|p| self.config.trust.is_trusted_publisher(p))
        });

        // Hash only when it can change the verdict: a trusted-publisher binary is already
        // green, so skip the expensive SHA-256 unless we have a baseline to look it up against.
        let hash_start = Instant::now();
        let sha256 = if self.store.is_some() && !trusted_pub {
            image_path.and_then(|p| hash::hash_file(p).ok())
        } else {
            None
        };
        let hash_ms = hash_start.elapsed().as_millis() as u64;

        // Identity ("what it looks like") from the curated knowledge base — an in-memory
        // lookup by name, not a per-file version-resource read.
        let description = crate::knowledge::describe(name).map(str::to_string);

        let record = ProcessRecord {
            pid,
            name: name.to_string(),
            image_path: image_path.map(Into::into),
            command_line: None,
            sha256: sha256.clone(),
            ppid: 0,
            parent_name: parent_name.map(Into::into),
            user: None,
            integrity_level: None,
            signature,
            network: vec![],
            collected_at: String::new(),
            errors: vec![],
        };

        let baseline = self.store.as_ref().and_then(|s| {
            sha256
                .as_deref()
                .and_then(|h| queries::get_known(&s.conn, h).ok().flatten())
        });
        let result = score::score(&record, &self.config, baseline.as_ref());

        let total_ms = start.elapsed().as_millis() as u64;
        if total_ms >= 500 {
            tracing::warn!(
                pid,
                name,
                path = image_path.unwrap_or(""),
                total_ms,
                hash_ms,
                sig_ms,
                verdict = ?result.verdict,
                "slow verify"
            );
        } else {
            tracing::debug!(pid, name, total_ms, hash_ms, sig_ms, verdict = ?result.verdict, "verified");
        }

        CachedVerdict {
            signed,
            publisher,
            description,
            sha256,
            verdict: result.verdict,
            score: result.score,
            fired_rules: result.fired_rules,
        }
    }

    /// Update the VirusTotal API key at runtime: enable reputation, (re)spawn the worker with
    /// the new key (the old worker exits when its channel drops), and clear the request-dedup
    /// set so the tail is re-queried with the new key.
    pub fn set_vt_key(&mut self, key: String) {
        self.config.reputation.api_key = Some(key);
        self.config.reputation.enabled = true;
        self.rep_requested.clear();
        #[cfg(feature = "reputation")]
        {
            self.rep_tx = if self.store.is_some() {
                self.config.reputation.api_key.clone().map(|k| {
                    crate::reputation::spawn_vt_worker(self.config.store.db_path.clone(), k)
                })
            } else {
                None
            };
        }
        tracing::info!("reputation: VirusTotal key updated at runtime");
    }

    /// Attempt to terminate a process. Returns Ok(true) if the kill signal was sent, Ok(false)
    /// if the process couldn't be killed (e.g. protected/insufficient rights or already gone).
    pub fn kill(&mut self, pid: u32) -> bool {
        let ok = match self.sys.process(Pid::from_u32(pid)) {
            Some(p) => p.kill(),
            None => false,
        };
        tracing::info!(pid, ok, "kill requested");
        ok
    }
}
