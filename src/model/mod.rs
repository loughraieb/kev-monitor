//! The data contract. These structs are the integration boundary with the management
//! plane — keep field names and shapes stable. The final emitted object per process is
//! [`Emitted`] (`{ record, result }`).

use serde::{Deserialize, Serialize};

/// One process plus all forensic signals collected for it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProcessRecord {
    pub pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub sha256: Option<String>,
    pub ppid: u32,
    pub parent_name: Option<String>,
    pub user: Option<String>,
    /// Best-effort Windows integrity level (e.g. "System", "High"). Filled in Phase 5.
    pub integrity_level: Option<String>,
    pub signature: Option<Signature>,
    /// Established/listening sockets owned by this pid. Empty until Phase 7.
    pub network: Vec<NetworkConn>,
    /// RFC3339 timestamp of when this record was collected.
    pub collected_at: String,
    /// Per-process, non-fatal collection failures (e.g. "hash: access denied").
    pub errors: Vec<String>,
}

/// Authenticode signature summary for the image file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Signature {
    pub signed: bool,
    pub publisher: Option<String>,
    pub chain_valid: bool,
    pub revoked: bool,
}

/// A single network connection owned by a process.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetworkConn {
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
}

/// Overall trust verdict, ordered least → most suspicious.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Trusted,
    UnknownSigned,
    Suspicious,
    Malicious,
}

/// Scoring outcome with explainability.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScoreResult {
    pub verdict: Verdict,
    /// Higher = more suspicious.
    pub score: i32,
    /// Names of the rules that fired — why this verdict.
    pub fired_rules: Vec<String>,
}

/// The final per-process object emitted to stdout.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Emitted {
    pub record: ProcessRecord,
    pub result: Option<ScoreResult>,
}
