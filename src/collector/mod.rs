//! Collector orchestration. Runs one full scan: enumerate processes, then enrich each
//! with hash and signature. The cardinal rule — one unreadable/odd process must never
//! abort the scan. Per-process failures land in `ProcessRecord.errors`.

pub mod hash;
pub mod network;
pub mod process;
pub mod signature;
pub mod version;

use std::panic::{catch_unwind, AssertUnwindSafe};

use sysinfo::Users;

use crate::config::Config;
use crate::model::ProcessRecord;

/// Enumerate and enrich every running process.
pub fn scan(config: &Config) -> Vec<ProcessRecord> {
    let sys = process::refreshed_system();
    let users = Users::new_with_refreshed_list();
    let now = chrono::Utc::now().to_rfc3339();

    let mut records = process::collect_base_records(&sys, &users, &now);
    for record in &mut records {
        enrich(record, config);
    }
    records
}

/// Enrich a single base record in place with hash + signature. Never panics out.
fn enrich(record: &mut ProcessRecord, config: &Config) {
    let Some(path) = record.image_path.clone() else {
        record.errors.push("image_path unavailable".into());
        return;
    };

    match hash::hash_file(&path) {
        Ok(h) => record.sha256 = Some(h),
        Err(e) => record.errors.push(format!("hash: {e}")),
    }

    // `verify_file` is designed never to panic, but isolate it anyway: a panic unwinding
    // through generated FFI must not take down the whole scan.
    let online = config.signature.online_revocation;
    match catch_unwind(AssertUnwindSafe(|| signature::verify_file(&path, online))) {
        Ok(sig) => {
            if let Some(err) = &sig.error {
                record.errors.push(format!("signature: {err}"));
            }
            record.signature = Some(sig.into());
        }
        Err(_) => record.errors.push("signature: verifier panicked".into()),
    }
}
