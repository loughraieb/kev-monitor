//! Phase 2 — streaming SHA256 of a process image file via `sha2` 0.11.
//!
//! Returns an `Err` on access-denied / missing file; the collector records that in
//! `ProcessRecord.errors` and leaves `sha256` as `None`. Many protected/SYSTEM images
//! (and PID 0/4) deny reads even when elevated — that is expected, not fatal.

use std::fs::File;
use std::io::Read;

use sha2::{Digest, Sha256};

/// Compute the lowercase-hex SHA256 of the file at `path`, streaming in 64 KiB chunks.
pub fn hash_file(path: &str) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}
