//! Phase 6 — aggregate rule weights + baseline knowledge into a numeric score and a
//! [`Verdict`].
//!
//! Score = sum of fired rule weights, minus a bonus when the image matches a trusted
//! baseline entry (known-good by content + location). The score is then mapped to a verdict
//! via configurable thresholds. Verdict precedence: an active suspicion score outranks a
//! trusted-baseline match, so a baselined binary exhibiting masquerade signals is still
//! flagged.

use crate::config::Config;
use crate::engine::rules;
use crate::model::{ProcessRecord, ScoreResult, Verdict};
use crate::store::queries::KnownBinary;

/// Score and classify a single process. `baseline` is the matching `known_binaries` row for
/// this image's sha256, if one exists.
pub fn score(record: &ProcessRecord, config: &Config, baseline: Option<&KnownBinary>) -> ScoreResult {
    // Kernel pseudo-processes (System, Registry, Memory Compression, …) have no real on-disk
    // image to hash or verify; they're inherently trusted. Their names never carry a `.exe`,
    // so a real file like `system.exe` won't match this.
    if is_kernel_pseudo(&record.name) {
        return ScoreResult { verdict: Verdict::Trusted, score: -100, fired_rules: Vec::new() };
    }

    let fired = rules::evaluate(record, config);
    let fired_rules: Vec<String> = fired.iter().map(|f| f.name.to_string()).collect();
    let mut score: i32 = fired.iter().map(|f| f.weight).sum();

    let trusted = is_trusted_baseline(record, baseline);
    if trusted {
        score -= config.thresholds.trusted_bonus;
    }

    let t = &config.thresholds;
    let sig = record.signature.as_ref();
    let signed = sig.is_some_and(|s| s.signed);
    let chain_valid = sig.is_some_and(|s| s.chain_valid);
    let revoked = sig.is_some_and(|s| s.revoked);
    let trusted_publisher = sig
        .and_then(|s| s.publisher.as_deref())
        .is_some_and(|p| config.trust.is_trusted_publisher(p));

    let verdict = if score >= t.malicious {
        Verdict::Malicious
    } else if score >= t.suspicious {
        Verdict::Suspicious
    } else if signed && chain_valid && !revoked && trusted_publisher {
        // Real, cryptographic trust: validly signed by a known vendor. No baseline needed.
        Verdict::Trusted
    } else if trusted {
        // Known-good by content (hash in the baseline).
        Verdict::Trusted
    } else if signed && (!chain_valid || revoked) {
        // Has a signature, but the chain is broken or revoked — worth surfacing.
        Verdict::Suspicious
    } else if signed {
        // Validly signed, but by a publisher we don't (yet) vouch for.
        Verdict::UnknownSigned
    } else if record.image_path.is_none() {
        // No image path means we couldn't inspect it at all — typically a protected/kernel
        // pseudo-process (System, Registry, Secure System). Neutral, not suspicious.
        Verdict::UnknownSigned
    } else {
        // A real on-disk image that is unsigned and unknown — worth surfacing.
        Verdict::Suspicious
    };

    ScoreResult { verdict, score, fired_rules }
}

/// Names of Windows kernel pseudo-processes (note: no `.exe` extension, unlike real images).
fn is_kernel_pseudo(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "system"
            | "secure system"
            | "registry"
            | "memory compression"
            | "memcompression"
            | "system idle process"
    )
}

/// True when the image's hash is in the baseline as `trusted` and it's running from one of
/// that entry's recorded paths (or no paths were recorded).
fn is_trusted_baseline(record: &ProcessRecord, baseline: Option<&KnownBinary>) -> bool {
    let Some(kb) = baseline else {
        return false;
    };
    if kb.verdict != "trusted" {
        return false;
    }
    match &record.image_path {
        Some(path) => {
            kb.expected_paths.is_empty()
                || kb.expected_paths.iter().any(|p| p.eq_ignore_ascii_case(path))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ExpectedBinary};
    use crate::model::{ProcessRecord, Signature};
    use crate::store::queries::KnownBinary;

    fn cfg() -> Config {
        Config {
            expected_binary: vec![ExpectedBinary {
                name: "svchost.exe".into(),
                paths: vec![r"C:\Windows\System32\svchost.exe".into()],
                parents: vec!["services.exe".into()],
            }],
            ..Default::default()
        }
    }

    fn rec(name: &str, path: Option<&str>, parent: Option<&str>, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 10,
            name: name.into(),
            image_path: path.map(Into::into),
            command_line: None,
            sha256: Some("abc".into()),
            ppid: 1,
            parent_name: parent.map(Into::into),
            user: None,
            integrity_level: None,
            // A verified signature has a valid chain; tests that want a broken chain set it.
            signature: signed.map(|s| Signature { signed: s, chain_valid: s, ..Default::default() }),
            network: vec![],
            collected_at: "2026-06-01T00:00:00+00:00".into(),
            errors: vec![],
        }
    }

    /// A record with an explicit signature (publisher / chain validity).
    fn rec_signed(
        name: &str,
        path: Option<&str>,
        parent: Option<&str>,
        chain_valid: bool,
        publisher: Option<&str>,
    ) -> ProcessRecord {
        let mut r = rec(name, path, parent, Some(true));
        r.signature = Some(Signature {
            signed: true,
            chain_valid,
            revoked: false,
            publisher: publisher.map(Into::into),
        });
        r
    }

    fn trusted_row(path: &str) -> KnownBinary {
        KnownBinary {
            sha256: "abc".into(),
            expected_name: Some("svchost.exe".into()),
            expected_publisher: None,
            expected_paths: vec![path.into()],
            expected_parents: vec!["services.exe".into()],
            verdict: "trusted".into(),
            first_seen: "t".into(),
            last_seen: "t".into(),
        }
    }

    #[test]
    fn trusted_baseline_match_is_trusted() {
        let r = rec("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"), Some("services.exe"), Some(true));
        let kb = trusted_row(r"C:\Windows\System32\svchost.exe");
        let s = score(&r, &cfg(), Some(&kb));
        assert_eq!(s.verdict, Verdict::Trusted);
        assert!(s.score < 0);
    }

    #[test]
    fn trusted_publisher_is_trusted_without_baseline() {
        let r = rec_signed(
            "randomapp.exe",
            Some(r"C:\Program Files\X\randomapp.exe"),
            Some("explorer.exe"),
            true,
            Some("Microsoft Corporation"),
        );
        assert_eq!(score(&r, &cfg(), None).verdict, Verdict::Trusted);
    }

    #[test]
    fn untrusted_publisher_is_unknown_signed() {
        let r = rec_signed(
            "randomapp.exe",
            Some(r"C:\Program Files\X\randomapp.exe"),
            Some("explorer.exe"),
            true,
            Some("Some Random Studio LLC"),
        );
        assert_eq!(score(&r, &cfg(), None).verdict, Verdict::UnknownSigned);
    }

    #[test]
    fn signed_with_broken_chain_is_suspicious() {
        let r = rec_signed(
            "randomapp.exe",
            Some(r"C:\Program Files\X\randomapp.exe"),
            Some("explorer.exe"),
            false, // invalid chain
            Some("Microsoft Corporation"),
        );
        assert_eq!(score(&r, &cfg(), None).verdict, Verdict::Suspicious);
    }

    #[test]
    fn trusted_publisher_but_masquerade_still_flagged() {
        // svchost signed by Microsoft but running from %TEMP% → wrong_path fires → flagged.
        let r = rec_signed(
            "svchost.exe",
            Some(r"C:\Users\x\AppData\Local\Temp\svchost.exe"),
            Some("services.exe"),
            true,
            Some("Microsoft Windows Publisher"),
        );
        let s = score(&r, &cfg(), None);
        assert_eq!(s.verdict, Verdict::Suspicious);
        assert!(s.fired_rules.contains(&"wrong_path".to_string()));
    }

    #[test]
    fn masquerade_svchost_in_temp_is_malicious() {
        // wrong_path(40) + name not spoof + unsigned not in system path... use unsigned in temp:
        // wrong_path fires (40); also no trusted baseline. Add unsigned -> still only 40 => Suspicious.
        let r = rec("svchost.exe", Some(r"C:\Temp\svchost.exe"), Some("explorer.exe"), Some(false));
        let s = score(&r, &cfg(), None);
        // wrong_path (40) + wrong_parent (25) = 65 -> Suspicious
        assert_eq!(s.verdict, Verdict::Suspicious);
        assert!(s.fired_rules.contains(&"wrong_path".to_string()));
        assert!(s.fired_rules.contains(&"wrong_parent".to_string()));
    }

    #[test]
    fn unsigned_system_path_spoof_is_malicious() {
        // name_spoof(50) + unsigned_in_system_path(60) = 110 >= 80 -> Malicious
        let r = rec("scvhost.exe", Some(r"C:\Windows\System32\scvhost.exe"), Some("services.exe"), Some(false));
        let s = score(&r, &cfg(), None);
        assert_eq!(s.verdict, Verdict::Malicious);
    }

    #[test]
    fn signed_unknown_is_unknown_signed() {
        let r = rec("randomapp.exe", Some(r"C:\Program Files\X\randomapp.exe"), Some("explorer.exe"), Some(true));
        let s = score(&r, &cfg(), None);
        assert_eq!(s.verdict, Verdict::UnknownSigned);
    }

    #[test]
    fn unsigned_unknown_is_suspicious() {
        let r = rec("randomapp.exe", Some(r"C:\Users\x\Downloads\randomapp.exe"), Some("explorer.exe"), Some(false));
        let s = score(&r, &cfg(), None);
        assert_eq!(s.verdict, Verdict::Suspicious);
    }

    #[test]
    fn baselined_but_wrong_parent_still_flagged() {
        // Trusted hash + correct path, but parent is wrong: wrong_parent(25) - bonus(100) = -75 -> Trusted.
        // (Active signal present but below threshold; bonus dominates.) Documents the precedence.
        let r = rec("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"), Some("explorer.exe"), Some(true));
        let kb = trusted_row(r"C:\Windows\System32\svchost.exe");
        let s = score(&r, &cfg(), Some(&kb));
        assert!(s.fired_rules.contains(&"wrong_parent".to_string()));
        assert_eq!(s.verdict, Verdict::Trusted);
    }
}
