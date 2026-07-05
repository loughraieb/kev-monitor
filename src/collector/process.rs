//! Phase 1 — process enumeration via `sysinfo` 0.39.
//!
//! Produces a base [`ProcessRecord`] per running process with pid, name, image path,
//! command line, parent, user, and collection timestamp. Hash/signature/network are
//! filled by later collector stages.

use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind, Users};

use crate::model::ProcessRecord;

/// Build a `System` refreshed with exactly the process fields we need (exe, cmd, user).
pub fn refreshed_system() -> System {
    let proc_kind = ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::Always)
        .with_exe(UpdateKind::Always)
        .with_user(UpdateKind::Always);
    System::new_with_specifics(RefreshKind::nothing().with_processes(proc_kind))
}

/// Enumerate all processes into base records. `now_rfc3339` is captured once by the caller
/// so every record in a scan shares the same `collected_at`.
pub fn collect_base_records(sys: &System, users: &Users, now_rfc3339: &str) -> Vec<ProcessRecord> {
    sys.processes()
        .iter()
        .map(|(pid, proc_)| base_record(*pid, proc_, sys, users, now_rfc3339))
        .collect()
}

fn base_record(
    pid: sysinfo::Pid,
    proc_: &sysinfo::Process,
    sys: &System,
    users: &Users,
    now_rfc3339: &str,
) -> ProcessRecord {
    let image_path = proc_.exe().map(|p| p.to_string_lossy().into_owned());

    let cmd = proc_.cmd();
    let command_line = if cmd.is_empty() {
        None
    } else {
        Some(
            cmd.iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
        )
    };

    let parent = proc_.parent();
    let ppid = parent.map(|p| p.as_u32()).unwrap_or(0);
    let parent_name = parent
        .and_then(|pp| sys.process(pp))
        .map(|pp| pp.name().to_string_lossy().into_owned());

    let user = proc_
        .user_id()
        .and_then(|uid| users.get_user_by_id(uid))
        .map(|u| u.name().to_string());

    ProcessRecord {
        pid: pid.as_u32(),
        name: proc_.name().to_string_lossy().into_owned(),
        image_path,
        command_line,
        sha256: None,
        ppid,
        parent_name,
        user,
        integrity_level: None,
        signature: None,
        network: Vec::new(),
        collected_at: now_rfc3339.to_string(),
        errors: Vec::new(),
    }
}
