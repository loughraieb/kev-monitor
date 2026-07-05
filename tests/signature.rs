//! Integration tests for Phase 3 signature verification. Windows-only.
//!
//! Revocation is left at the caller's discretion; these assert primarily on `signed` and
//! `chain_valid`, treating `revoked` as network-dependent (not hard-asserted).

#![cfg(windows)]

use kev::collector::signature::verify_file;

#[test]
fn notepad_is_signed() {
    let path = r"C:\Windows\System32\notepad.exe";
    // Offline revocation for determinism in CI; signed/chain_valid don't need the network.
    let r = verify_file(path, false);
    assert!(r.signed, "notepad should be signed; error={:?}", r.error);
    assert!(r.chain_valid, "notepad chain should be valid; error={:?}", r.error);
    assert!(!r.revoked, "notepad should not be revoked");
}

#[test]
fn own_unsigned_exe_is_unsigned() {
    // The compiled test harness itself is unsigned.
    let exe = std::env::current_exe().expect("current_exe");
    let r = verify_file(exe.to_str().expect("utf8 path"), false);
    assert!(!r.signed, "freshly built exe should be unsigned; got {r:?}");
}

#[test]
fn missing_file_does_not_panic() {
    let r = verify_file(r"C:\does\not\exist\nope.exe", false);
    assert!(!r.signed);
    // Should report an error rather than claim a valid signature.
    assert!(r.error.is_some() || !r.chain_valid);
}
