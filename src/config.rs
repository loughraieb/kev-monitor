//! Runtime configuration, loaded from `config.toml`. Everything has a sensible default
//! so a missing file (or missing keys) still yields a working config. Later phases extend
//! this with expected system-binary paths/parents, name-spoof targets, rule weights, and
//! verdict thresholds.

use std::path::Path;

use serde::Deserialize;

/// Top-level configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub signature: SignatureConfig,
    pub store: StoreConfig,
    pub reputation: ReputationConfig,
    pub rules: RulesConfig,
    pub thresholds: Thresholds,
    pub trust: TrustConfig,
    /// Expected locations/parents for well-known system binaries, used by the
    /// `wrong_path` / `wrong_parent` rules and as `name_spoof` targets.
    pub expected_binary: Vec<ExpectedBinary>,
}

/// Publisher-trust settings: a signed binary whose Authenticode publisher matches one of these
/// (case-insensitive substring) is trusted without needing a per-hash baseline.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TrustConfig {
    pub trusted_publishers: Vec<String>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            trusted_publishers: [
                "Microsoft Windows",
                "Microsoft Corporation",
                "Microsoft Windows Publisher",
                "Google LLC",
                "Intel",
                "Dell",
                "NVIDIA",
                "Realtek",
                "Mozilla Corporation",
                "Valve",
                "Lenovo",
                "Advanced Micro Devices",
                "Logitech",
                "Apple Inc.",
                "Hewlett-Packard",
                "HP Inc.",
                "Qualcomm",
                "Synaptics",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

impl TrustConfig {
    /// True if `publisher` matches a trusted vendor (case-insensitive substring).
    pub fn is_trusted_publisher(&self, publisher: &str) -> bool {
        let p = publisher.to_ascii_lowercase();
        self.trusted_publishers
            .iter()
            .any(|e| !e.is_empty() && p.contains(&e.to_ascii_lowercase()))
    }
}

/// Score cutoffs that map a numeric suspicion score to a [`crate::model::Verdict`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Score at/above which a process is `Suspicious`.
    pub suspicious: i32,
    /// Score at/above which a process is `Malicious`.
    pub malicious: i32,
    /// Suspicion points subtracted when a process matches a trusted baseline entry.
    pub trusted_bonus: i32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { suspicious: 30, malicious: 80, trusted_bonus: 100 }
    }
}

/// A protected system binary and where it is legitimately expected to run from.
#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedBinary {
    pub name: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub parents: Vec<String>,
}

/// Rule engine configuration: per-rule weights.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub weights: RuleWeights,
}

/// Weight (suspicion points) added when each rule fires.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuleWeights {
    pub wrong_path: i32,
    pub wrong_parent: i32,
    pub name_spoof: i32,
    pub unsigned_in_system_path: i32,
    pub untrusted_publisher_in_system_dir: i32,
}

impl Default for RuleWeights {
    fn default() -> Self {
        Self {
            wrong_path: 40,
            wrong_parent: 25,
            name_spoof: 50,
            unsigned_in_system_path: 60,
            untrusted_publisher_in_system_dir: 35,
        }
    }
}

/// VirusTotal reputation settings (used only with the `reputation` feature).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReputationConfig {
    /// Master switch. Even when true, lookups require an API key (env `VT_API_KEY` or `api_key`).
    pub enabled: bool,
    /// VirusTotal API key. Prefer the `VT_API_KEY` env var; this is for the runtime app config
    /// only and must never be committed to source.
    pub api_key: Option<String>,
    /// Detections at/above which VirusTotal alone makes a process Malicious.
    pub vt_malicious_threshold: i64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self { enabled: false, api_key: None, vt_malicious_threshold: 5 }
    }
}

/// Local store (SQLite) settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StoreConfig {
    /// Path to the SQLite database file (baseline, reputation cache, observations).
    pub db_path: String,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { db_path: "kev.db".to_string() }
    }
}

/// Signature-verification knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SignatureConfig {
    /// When true, Authenticode verification performs online (OCSP/CRL) revocation checks
    /// of the whole chain (`WTD_REVOKE_WHOLECHAIN`). When false, no revocation check is
    /// performed (`WTD_REVOKE_NONE`) — faster and offline, but `revoked` is never detected.
    pub online_revocation: bool,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self { online_revocation: true }
    }
}

/// Persist a new VirusTotal API key into a config file, enabling reputation. Preserves the
/// rest of the file (comments included): replaces `api_key`/`enabled` inside `[reputation]`,
/// or appends a `[reputation]` section if absent. Creates the file if missing.
pub fn write_vt_key(path: &Path, key: &str) -> std::io::Result<()> {
    let original = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = String::new();
    let mut in_rep = false;
    let (mut set_key, mut set_enabled, mut seen_rep) = (false, false, false);

    let flush = |out: &mut String, sk: &mut bool, se: &mut bool, key: &str| {
        if !*sk {
            out.push_str(&format!("api_key = \"{key}\"\n"));
            *sk = true;
        }
        if !*se {
            out.push_str("enabled = true\n");
            *se = true;
        }
    };

    for line in original.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            if in_rep {
                flush(&mut out, &mut set_key, &mut set_enabled, key);
            }
            in_rep = trimmed.starts_with("[reputation]");
            if in_rep {
                seen_rep = true;
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if in_rep {
            let t = trimmed.trim_start_matches('#').trim_start();
            if t.starts_with("api_key") {
                out.push_str(&format!("api_key = \"{key}\"\n"));
                set_key = true;
                continue;
            }
            if t.starts_with("enabled") {
                out.push_str("enabled = true\n");
                set_enabled = true;
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_rep {
        flush(&mut out, &mut set_key, &mut set_enabled, key);
    }
    if !seen_rep {
        out.push_str(&format!("\n[reputation]\nenabled = true\napi_key = \"{key}\"\n"));
    }
    std::fs::write(path, out)
}

/// A documented, key-less starter config written on first launch (when the user is prompted
/// about VirusTotal). Reputation is off; enabling it later — either by pressing `v` in the
/// monitor or editing this file — is handled by [`write_vt_key`], which uncomments/sets the
/// `api_key` and flips `enabled` to true.
pub const CONFIG_TEMPLATE: &str = "\
# kev configuration.
#
# kev works with no config file at all — this one was created so kev can remember
# your choices. Delete it to reset to first-launch behavior.

[reputation]
# VirusTotal cross-checks unknown files by hash. Only the file's SHA-256 is ever
# sent to VirusTotal — never the file itself. It is optional and off by default.
# To enable it, paste a free API key (https://www.virustotal.com/gui/my-apikey)
# below and set enabled = true — or just press `v` in the monitor.
enabled = false
# api_key = \"PASTE-YOUR-VIRUSTOTAL-API-KEY-HERE\"

[signature]
# Online certificate-revocation checks during one-shot scans. The live monitor is
# always offline for speed regardless of this setting.
online_revocation = true
";

/// Write [`CONFIG_TEMPLATE`] to `path` **only if the file does not already exist**, so an
/// existing (possibly key-bearing) config is never clobbered. Used to persist the user's
/// first-launch choice so they aren't prompted again.
pub fn write_default_template(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    std::fs::write(path, CONFIG_TEMPLATE)
}

impl Config {
    /// Load config from `path`. If `path` is `None` or the file does not exist, returns
    /// defaults. Parse errors are surfaced to the caller.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        use anyhow::Context;
        match path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                let cfg: Config = toml::from_str(&text)
                    .with_context(|| format!("parsing config {}", p.display()))?;
                Ok(cfg)
            }
            _ => Ok(Config::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("kev-{}-{}.toml", std::process::id(), name))
    }

    #[test]
    fn template_parses_and_starts_disabled() {
        let p = tmp("template");
        let _ = std::fs::remove_file(&p);
        write_default_template(&p).unwrap();
        let cfg = Config::load(Some(&p)).unwrap();
        assert!(!cfg.reputation.enabled);
        assert!(cfg.reputation.api_key.as_deref().unwrap_or("").is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn first_launch_then_key_enables_reputation() {
        // Simulates: welcome modal writes the starter file, user then pastes a key.
        let p = tmp("first-launch");
        let _ = std::fs::remove_file(&p);
        write_default_template(&p).unwrap();
        write_vt_key(&p, "DEADBEEF").unwrap();
        let cfg = Config::load(Some(&p)).unwrap();
        assert!(cfg.reputation.enabled, "key entry must flip enabled=true");
        assert_eq!(cfg.reputation.api_key.as_deref(), Some("DEADBEEF"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn template_never_clobbers_existing() {
        let p = tmp("no-clobber");
        std::fs::write(&p, "[reputation]\nenabled = true\napi_key = \"KEEP\"\n").unwrap();
        write_default_template(&p).unwrap(); // must be a no-op
        let cfg = Config::load(Some(&p)).unwrap();
        assert_eq!(cfg.reputation.api_key.as_deref(), Some("KEEP"));
        let _ = std::fs::remove_file(&p);
    }
}
