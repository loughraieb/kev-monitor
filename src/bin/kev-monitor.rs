//! Clickable launcher for the kev monitor.
//!
//! Double-clicking this (a GUI-subsystem exe, so no console flash of its own) opens
//! `kev.exe monitor` — in **Windows Terminal** when available (modern UI, smooth touchpad
//! scrolling), otherwise a plain console — prompting for admin via UAC first if we aren't
//! already elevated. Keep `kev.exe`, `config.toml`, and (after `kev baseline`) `kev.db` in
//! the same folder as this launcher.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// ShellExecute and report success (HINSTANCE > 32 per the Win32 contract).
    fn run(verb: &str, file: &str, params: &str, dir: &str) -> bool {
        let (verb, file, params, dir) = (wide(verb), wide(file), wide(params), wide(dir));
        // SAFETY: every PCWSTR points at a NUL-terminated buffer that lives across the call.
        let h = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(file.as_ptr()),
                PCWSTR(params.as_ptr()),
                PCWSTR(dir.as_ptr()),
                SW_SHOWNORMAL,
            )
        };
        (h.0 as isize) > 32
    }

    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().expect("exe dir").to_path_buf();
    let kev = dir.join("kev.exe");
    let dir_s = dir.to_string_lossy().into_owned();
    let kev_s = kev.to_string_lossy().into_owned();

    // "runas" raises the UAC prompt; if already elevated, "open" avoids a redundant one.
    let verb = if kev::platform::is_elevated() { "open" } else { "runas" };

    // Prefer Windows Terminal (its app-execution-alias) for a modern, scrollable window.
    let wt = std::env::var("LOCALAPPDATA")
        .map(|la| PathBuf::from(la).join(r"Microsoft\WindowsApps\wt.exe"))
        .ok()
        .filter(|p| p.exists());

    let launched = if let Some(wt) = &wt {
        // wt -d <dir> --title "…" <kev.exe> monitor
        let params = format!(
            "-d \"{dir_s}\" --title \"kev — process monitor\" \"{kev_s}\" monitor"
        );
        run(verb, &wt.to_string_lossy(), &params, &dir_s)
    } else {
        false
    };

    // Fallback: launch kev.exe directly in a plain console.
    if !launched {
        run(verb, &kev_s, "monitor", &dir_s);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("kev-monitor launcher is Windows-only; run `kev monitor` directly.");
}
