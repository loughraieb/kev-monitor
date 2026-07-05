//! Phase 5 — masquerade-detection rules.
//!
//! Each rule is a pure predicate over a [`ProcessRecord`] (+ [`Config`]), so they are unit
//! testable with fixtures and need no live processes. [`evaluate`] runs all rules and pairs
//! each that fires with its configured weight.

use crate::config::{Config, ExpectedBinary};
use crate::model::ProcessRecord;

/// A rule that fired, with the suspicion weight it contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiredRule {
    pub name: &'static str,
    pub weight: i32,
}

/// Run every rule against `record`; return those that fired (with weights from config).
pub fn evaluate(record: &ProcessRecord, config: &Config) -> Vec<FiredRule> {
    let w = &config.rules.weights;
    let mut fired = Vec::new();
    if wrong_path(record, config) {
        fired.push(FiredRule { name: "wrong_path", weight: w.wrong_path });
    }
    if wrong_parent(record, config) {
        fired.push(FiredRule { name: "wrong_parent", weight: w.wrong_parent });
    }
    if name_spoof(record, config) {
        fired.push(FiredRule { name: "name_spoof", weight: w.name_spoof });
    }
    if unsigned_in_system_path(record) {
        fired.push(FiredRule { name: "unsigned_in_system_path", weight: w.unsigned_in_system_path });
    }
    if untrusted_publisher_in_system_dir(record, config) {
        fired.push(FiredRule {
            name: "untrusted_publisher_in_system_dir",
            weight: w.untrusted_publisher_in_system_dir,
        });
    }
    fired
}

/// Find the expected-binary definition matching `name` (case-insensitive).
fn expected_for<'a>(name: &str, config: &'a Config) -> Option<&'a ExpectedBinary> {
    let stem = stem_lower(name);
    config.expected_binary.iter().find(|e| stem_lower(&e.name) == stem)
}

/// A process claiming a known system-binary name, but running from a path that isn't one of
/// its sanctioned locations.
pub fn wrong_path(record: &ProcessRecord, config: &Config) -> bool {
    let Some(exp) = expected_for(&record.name, config) else {
        return false;
    };
    if exp.paths.is_empty() {
        return false;
    }
    let Some(path) = &record.image_path else {
        return false;
    };
    !exp.paths.iter().any(|p| p.eq_ignore_ascii_case(path))
}

/// A process claiming a known system-binary name, but whose parent isn't one of its
/// sanctioned parents (e.g. `svchost.exe` whose parent isn't `services.exe`).
pub fn wrong_parent(record: &ProcessRecord, config: &Config) -> bool {
    let Some(exp) = expected_for(&record.name, config) else {
        return false;
    };
    if exp.parents.is_empty() {
        return false;
    }
    match &record.parent_name {
        Some(parent) => !exp.parents.iter().any(|p| p.eq_ignore_ascii_case(parent)),
        // We expect a specific parent but couldn't determine one: stay conservative.
        None => false,
    }
}

/// A process whose name is a near-miss of a protected system binary (typo, adjacent
/// transposition, or homoglyph) without actually being that binary — classic masquerade,
/// e.g. `scvhost.exe` or `lsass.exe` spelled with a capital `I`.
pub fn name_spoof(record: &ProcessRecord, config: &Config) -> bool {
    // A binary validly signed by a trusted vendor isn't spoofing a system name — it *is* that
    // vendor's own binary (e.g. Microsoft's LsaIso/SMSvcHost, close to lsass/svchost). An
    // attacker can't obtain such a signature, so suppress the rule here.
    if let Some(sig) = &record.signature {
        if sig.signed
            && sig.chain_valid
            && !sig.revoked
            && sig.publisher.as_deref().is_some_and(|p| config.trust.is_trusted_publisher(p))
        {
            return false;
        }
    }

    let name = stem_lower(&record.name);
    let canons: Vec<String> =
        config.expected_binary.iter().map(|e| stem_lower(&e.name)).collect();

    // Exactly a protected name → not a spoof (other rules judge imposters using the real name).
    if canons.contains(&name) {
        return false;
    }

    let name_folded = fold_confusables(&name);
    for canon in &canons {
        if canon.len() < 5 {
            continue; // too short — edit-distance noise
        }
        let canon_folded = fold_confusables(canon);
        // Homoglyph-only spoof: identical once confusable characters are folded.
        if name_folded == canon_folded {
            return true;
        }
        // Typo / adjacent-transposition spoof: small edit distance, similar length.
        let d = osa_distance(&name_folded, &canon_folded);
        if (1..=2).contains(&d) && name.len().abs_diff(canon.len()) <= 2 {
            return true;
        }
    }
    false
}

/// A process that verification reports as unsigned while running from `System32`/`SysWOW64`.
/// A signature of `None` (couldn't verify) does not fire — only a confirmed-unsigned image.
pub fn unsigned_in_system_path(record: &ProcessRecord) -> bool {
    let Some(sig) = &record.signature else {
        return false;
    };
    if sig.signed {
        return false;
    }
    let Some(path) = &record.image_path else {
        return false;
    };
    let p = path.to_ascii_lowercase();
    p.contains("\\windows\\system32\\") || p.contains("\\windows\\syswow64\\")
}

/// A validly-signed binary running from `System32`/`SysWOW64` whose publisher we don't trust.
/// The system directories should hold OS/trusted-vendor binaries; a signed-but-unknown-vendor
/// image there is worth surfacing.
pub fn untrusted_publisher_in_system_dir(record: &ProcessRecord, config: &Config) -> bool {
    let Some(sig) = &record.signature else {
        return false;
    };
    if !(sig.signed && sig.chain_valid && !sig.revoked) {
        return false;
    }
    let Some(publisher) = sig.publisher.as_deref() else {
        return false;
    };
    if config.trust.is_trusted_publisher(publisher) {
        return false;
    }
    let Some(path) = &record.image_path else {
        return false;
    };
    let p = path.to_ascii_lowercase();
    p.contains("\\windows\\system32\\") || p.contains("\\windows\\syswow64\\")
}

// --- helpers ---

/// Lowercase file-name stem (drops any directory components).
fn stem_lower(name: &str) -> String {
    name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase()
}

/// Fold visually-confusable characters to a canonical representative so homoglyph swaps
/// (capital-I/lowercase-l/one, zero/o, five/s) compare equal.
fn fold_confusables(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '1' | 'i' | 'l' | '|' => 'l',
            '0' => 'o',
            '5' => 's',
            other => other,
        })
        .collect()
}

/// Optimal string alignment (restricted Damerau-Levenshtein) distance, counting an adjacent
/// transposition as a single edit.
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut best = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[n][m]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ExpectedBinary};
    use crate::model::{ProcessRecord, Signature};

    fn cfg() -> Config {
        Config {
            expected_binary: vec![
                ExpectedBinary {
                    name: "svchost.exe".into(),
                    paths: vec![
                        r"C:\Windows\System32\svchost.exe".into(),
                        r"C:\Windows\SysWOW64\svchost.exe".into(),
                    ],
                    parents: vec!["services.exe".into()],
                },
                ExpectedBinary {
                    name: "lsass.exe".into(),
                    paths: vec![r"C:\Windows\System32\lsass.exe".into()],
                    parents: vec!["wininit.exe".into()],
                },
            ],
            ..Default::default()
        }
    }

    fn rec(name: &str, path: Option<&str>, parent: Option<&str>, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 1234,
            name: name.into(),
            image_path: path.map(Into::into),
            command_line: None,
            sha256: None,
            ppid: 1,
            parent_name: parent.map(Into::into),
            user: None,
            integrity_level: None,
            signature: signed.map(|s| Signature { signed: s, ..Default::default() }),
            network: vec![],
            collected_at: "2026-06-01T00:00:00+00:00".into(),
            errors: vec![],
        }
    }

    #[test]
    fn legit_svchost_fires_nothing() {
        let r = rec("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"), Some("services.exe"), Some(true));
        assert!(evaluate(&r, &cfg()).is_empty());
    }

    #[test]
    fn svchost_in_temp_is_wrong_path() {
        let r = rec("svchost.exe", Some(r"C:\Users\x\AppData\Local\Temp\svchost.exe"), Some("services.exe"), Some(true));
        assert!(wrong_path(&r, &cfg()));
        let fired: Vec<_> = evaluate(&r, &cfg()).into_iter().map(|f| f.name).collect();
        assert!(fired.contains(&"wrong_path"));
    }

    #[test]
    fn svchost_wrong_parent() {
        let r = rec("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"), Some("explorer.exe"), Some(true));
        assert!(wrong_parent(&r, &cfg()));
        assert!(!wrong_path(&r, &cfg()));
    }

    #[test]
    fn unknown_name_no_path_or_parent_rules() {
        let r = rec("myapp.exe", Some(r"C:\Program Files\App\myapp.exe"), Some("explorer.exe"), Some(true));
        assert!(!wrong_path(&r, &cfg()));
        assert!(!wrong_parent(&r, &cfg()));
    }

    #[test]
    fn transposition_is_name_spoof() {
        // scvhost vs svchost (adjacent transposition)
        let r = rec("scvhost.exe", Some(r"C:\Temp\scvhost.exe"), Some("explorer.exe"), Some(false));
        assert!(name_spoof(&r, &cfg()));
    }

    #[test]
    fn trusted_publisher_suppresses_name_spoof() {
        // A lookalike that is VALIDLY signed by a trusted vendor isn't a spoof (e.g. Microsoft's
        // own LsaIso/SMSvcHost, close to lsass/svchost).
        let mut r = rec("scvhost.exe", Some(r"C:\x\scvhost.exe"), Some("services.exe"), Some(true));
        r.signature = Some(crate::model::Signature {
            signed: true,
            chain_valid: true,
            revoked: false,
            publisher: Some("Microsoft Windows".into()),
        });
        assert!(!name_spoof(&r, &cfg()));
        // The same lookalike unsigned still fires.
        let r2 = rec("scvhost.exe", Some(r"C:\x\scvhost.exe"), Some("services.exe"), Some(false));
        assert!(name_spoof(&r2, &cfg()));
    }

    #[test]
    fn homoglyph_is_name_spoof() {
        // lsass spelled with a capital I -> lowercases to "isass.exe"
        let r = rec("Isass.exe", Some(r"C:\Temp\Isass.exe"), None, Some(false));
        assert!(name_spoof(&r, &cfg()));
    }

    #[test]
    fn real_name_is_not_spoof() {
        let r = rec("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"), Some("services.exe"), Some(true));
        assert!(!name_spoof(&r, &cfg()));
    }

    #[test]
    fn unrelated_name_is_not_spoof() {
        let r = rec("chrome.exe", Some(r"C:\Program Files\Google\Chrome\chrome.exe"), Some("explorer.exe"), Some(true));
        assert!(!name_spoof(&r, &cfg()));
    }

    #[test]
    fn untrusted_publisher_in_system32() {
        let sig = |pubr: &str| crate::model::Signature {
            signed: true,
            chain_valid: true,
            revoked: false,
            publisher: Some(pubr.into()),
        };
        let mut r = rec("vendor.exe", Some(r"C:\Windows\System32\vendor.exe"), None, Some(true));
        r.signature = Some(sig("Random Vendor LLC"));
        assert!(untrusted_publisher_in_system_dir(&r, &cfg()));
        // Trusted vendor in System32 → fine.
        let mut r2 = rec("ok.exe", Some(r"C:\Windows\System32\ok.exe"), None, Some(true));
        r2.signature = Some(sig("Microsoft Windows"));
        assert!(!untrusted_publisher_in_system_dir(&r2, &cfg()));
        // Untrusted vendor outside System32 → fine.
        let mut r3 = rec("vendor.exe", Some(r"C:\Program Files\V\vendor.exe"), None, Some(true));
        r3.signature = Some(sig("Random Vendor LLC"));
        assert!(!untrusted_publisher_in_system_dir(&r3, &cfg()));
    }

    #[test]
    fn unsigned_in_system32_fires() {
        let r = rec("evil.exe", Some(r"C:\Windows\System32\evil.exe"), None, Some(false));
        assert!(unsigned_in_system_path(&r));
    }

    #[test]
    fn signed_in_system32_does_not_fire() {
        let r = rec("legit.exe", Some(r"C:\Windows\System32\legit.exe"), None, Some(true));
        assert!(!unsigned_in_system_path(&r));
    }

    #[test]
    fn unknown_signature_does_not_fire_unsigned_rule() {
        let r = rec("x.exe", Some(r"C:\Windows\System32\x.exe"), None, None);
        assert!(!unsigned_in_system_path(&r));
    }

    #[test]
    fn osa_basic() {
        assert_eq!(osa_distance("svchost", "scvhost"), 1); // transposition
        assert_eq!(osa_distance("svchost", "svhost"), 1); // deletion
        assert_eq!(osa_distance("abc", "abc"), 0);
    }
}
