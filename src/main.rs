//! kev CLI. JSON results go to **stdout**; all logs/diagnostics go to **stderr**.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use kev::collector;
use kev::config::Config;
use kev::engine;
use kev::model::{Emitted, ProcessRecord};
use kev::store::queries::{self, UpsertKind};
use kev::store::Store;

#[derive(Parser)]
#[command(name = "kev", version, about = "Windows process-legitimacy agent")]
struct Cli {
    /// Pretty-print JSON output.
    #[arg(long, global = true)]
    pretty: bool,
    /// Path to config.toml (defaults to ./config.toml if present).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Write logs to this file instead of stderr. `monitor` defaults to `kev.log`.
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,
    /// Verbose logging (debug level). Overridden by the RUST_LOG env var.
    #[arg(long, short = 'v', global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enumerate + enrich + score every process; print a JSON array to stdout.
    Scan,
    /// Seed the known-good baseline from this (clean) machine into the store.
    Baseline {
        /// Don't write — just report how many binaries would be baselined.
        #[arg(long)]
        dry_run: bool,
    },
    /// Deep-check a single target by --path (file) or --pid (process).
    Verify {
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Live, colored process monitor (Task-Manager style) with kill + resource usage.
    Monitor {
        /// Headless: print one JSON snapshot instead of the interactive UI.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // `monitor` runs a full-screen TUI that owns the terminal, so stderr logs would corrupt
    // it — default that command to a log file.
    let log_file = cli.log_file.clone().or_else(|| {
        matches!(cli.cmd, Cmd::Monitor { .. }).then(|| PathBuf::from("kev.log"))
    });
    let _log_guard = init_tracing(log_file.as_deref(), cli.verbose);
    if let Some(path) = &log_file {
        tracing::info!("kev starting — logging to {}", path.display());
    }

    let config_path = cli.config.clone().or_else(|| {
        let default = PathBuf::from("config.toml");
        default.exists().then_some(default)
    });
    let config = Config::load(config_path.as_deref()).context("loading config")?;

    if !kev::platform::is_elevated() {
        tracing::warn!(
            "not running elevated — image paths/hashes of SYSTEM-owned processes may be unreadable (degraded coverage)"
        );
    }

    match cli.cmd {
        Cmd::Scan => {
            let records = collector::scan(&config);
            let emitted = score_records(records, &config);
            print_json(&emitted, cli.pretty)?;
        }
        Cmd::Verify { path, pid } => run_verify(&config, path, pid, cli.pretty)?,
        Cmd::Baseline { dry_run } => run_baseline(&config, dry_run, cli.pretty)?,
        Cmd::Monitor { json } => {
            if json {
                kev::monitor::tui::run_json(config)?;
            } else {
                kev::monitor::tui::run(config, config_path)?;
            }
        }
    }
    Ok(())
}

fn run_verify(
    config: &Config,
    path: Option<String>,
    pid: Option<u32>,
    pretty: bool,
) -> anyhow::Result<()> {
    match (path, pid) {
        (Some(_), Some(_)) => anyhow::bail!("pass only one of --path or --pid"),
        (None, None) => anyhow::bail!("pass --path <FILE> or --pid <PID>"),
        (Some(path), None) => {
            let sha256 = collector::hash::hash_file(&path).ok();
            let sig = collector::signature::verify_file(&path, config.signature.online_revocation);
            let out = serde_json::json!({
                "path": path,
                "sha256": sha256,
                "signature": {
                    "signed": sig.signed,
                    "publisher": sig.publisher,
                    "chain_valid": sig.chain_valid,
                    "revoked": sig.revoked,
                    "error": sig.error,
                }
            });
            print_json(&out, pretty)?;
        }
        (None, Some(pid)) => {
            let records = collector::scan(config);
            let emitted = score_records(records, config);
            match emitted.into_iter().find(|e| e.record.pid == pid) {
                Some(e) => print_json(&e, pretty)?,
                None => anyhow::bail!("no process with pid {pid}"),
            }
        }
    }
    Ok(())
}

/// One process eligible for the baseline (has both a hash and an image path).
struct BaselineCandidate {
    sha256: String,
    name: String,
    publisher: Option<String>,
    image_path: String,
    parent_name: Option<String>,
}

/// Score every record against the rules + baseline, producing the emitted `{record, result}`
/// objects. Opens the baseline store read-only if it exists; without it, scoring relies on
/// rules + signature only.
fn score_records(records: Vec<ProcessRecord>, config: &Config) -> Vec<Emitted> {
    let store = if std::path::Path::new(&config.store.db_path).exists() {
        match Store::open(&config.store.db_path) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("could not open baseline store: {e}; scoring without baseline");
                None
            }
        }
    } else {
        None
    };

    records
        .into_iter()
        .map(|record| {
            let baseline = store.as_ref().and_then(|s| {
                record
                    .sha256
                    .as_deref()
                    .and_then(|h| queries::get_known(&s.conn, h).ok().flatten())
            });
            let result = engine::score::score(&record, config, baseline.as_ref());
            Emitted { record, result: Some(result) }
        })
        .collect()
}

/// Seed the trusted baseline from a scan of this machine.
fn run_baseline(config: &Config, dry_run: bool, pretty: bool) -> anyhow::Result<()> {
    let records = collector::scan(config);
    // Only processes with both a hash and an image path can be baselined.
    let candidates: Vec<BaselineCandidate> = records
        .into_iter()
        .filter_map(|r| {
            Some(BaselineCandidate {
                sha256: r.sha256?,
                image_path: r.image_path?,
                publisher: r.signature.and_then(|s| s.publisher),
                name: r.name,
                parent_name: r.parent_name,
            })
        })
        .collect();

    if dry_run {
        let out = serde_json::json!({
            "dry_run": true,
            "db_path": config.store.db_path,
            "candidates": candidates.len(),
        });
        return print_json(&out, pretty);
    }

    let mut store = Store::open(&config.store.db_path)?;
    let now = chrono::Utc::now().to_rfc3339();
    let (mut inserted, mut updated) = (0u64, 0u64);
    {
        let tx = store.conn.transaction()?;
        for c in &candidates {
            match queries::upsert_baseline(
                &tx,
                &c.sha256,
                &c.name,
                c.publisher.as_deref(),
                &c.image_path,
                c.parent_name.as_deref(),
                &now,
            )? {
                UpsertKind::Inserted => inserted += 1,
                UpsertKind::Updated => updated += 1,
            }
        }
        tx.commit()?;
    }
    let total = queries::count_known(&store.conn)?;
    tracing::info!(inserted, updated, total, "baseline updated");
    let out = serde_json::json!({
        "dry_run": false,
        "db_path": config.store.db_path,
        "candidates": candidates.len(),
        "inserted": inserted,
        "updated": updated,
        "total_known_binaries": total,
    });
    print_json(&out, pretty)
}

fn print_json<T: serde::Serialize>(value: &T, pretty: bool) -> anyhow::Result<()> {
    let text = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    println!("{text}");
    Ok(())
}

/// Initialize tracing. With a `log_file`, logs go there (non-blocking) and the returned guard
/// must be held for the program's lifetime to flush on exit; otherwise logs go to stderr.
fn init_tracing(
    log_file: Option<&std::path::Path>,
    verbose: bool,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{fmt, EnvFilter};
    let default_level = if verbose { "debug" } else { "info" };
    let make_filter =
        || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    if let Some(path) = log_file {
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let (writer, guard) = tracing_appender::non_blocking(file);
            let _ = fmt()
                .with_writer(writer)
                .with_ansi(false)
                .with_env_filter(make_filter())
                .try_init();
            return Some(guard);
        }
    }
    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(make_filter())
        .try_init();
    None
}

