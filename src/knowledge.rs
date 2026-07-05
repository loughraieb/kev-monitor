//! Curated process knowledge base: a process file name → a concise (2–3 word) best-guess of
//! what it is. This is **identity only, not a trust signal** — a name can be spoofed, so the
//! verdict (signature/baseline/rules) is what judges legitimacy. This just answers "what does
//! this look like?".
//!
//! It replaces reading `FileDescription` from each binary at runtime: a constant-time
//! in-memory lookup instead of a per-file version-resource read (no file I/O). Extend
//! [`ENTRIES`] as we encounter new processes (keys are lowercase).

use std::collections::HashMap;
use std::sync::LazyLock;

static KB: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| ENTRIES.iter().copied().collect());

/// Best-guess short description for a process by file name (case-insensitive). `None` if the
/// process isn't in the knowledge base yet.
pub fn describe(name: &str) -> Option<&'static str> {
    KB.get(name.to_ascii_lowercase().as_str()).copied()
}

/// Number of entries — handy for tests / diagnostics.
pub fn len() -> usize {
    ENTRIES.len()
}

/// (lowercase process name, concise description). Keep descriptions to ~2–3 words.
const ENTRIES: &[(&str, &str)] = &[
    // --- Windows kernel / core ---
    ("system", "Windows kernel"),
    ("[system process]", "CPU idle process"),
    ("registry", "Registry kernel process"),
    ("secure system", "VBS secure kernel"),
    ("memory compression", "Memory compression"),
    ("smss.exe", "Session manager"),
    ("csrss.exe", "Client/server runtime"),
    ("wininit.exe", "Windows startup"),
    ("winlogon.exe", "Windows logon"),
    ("services.exe", "Service control manager"),
    ("lsass.exe", "Security authority (LSASS)"),
    ("lsaiso.exe", "Credential Guard"),
    ("svchost.exe", "Windows service host"),
    ("dwm.exe", "Desktop Window Manager"),
    ("explorer.exe", "Windows Explorer"),
    ("conhost.exe", "Console host"),
    ("openconsole.exe", "Console host"),
    ("taskhostw.exe", "Windows task host"),
    ("runtimebroker.exe", "Runtime broker"),
    ("dllhost.exe", "COM surrogate"),
    ("sihost.exe", "Shell infrastructure host"),
    ("ctfmon.exe", "Text input service"),
    ("fontdrvhost.exe", "Font driver host"),
    ("audiodg.exe", "Windows audio engine"),
    ("smartscreen.exe", "SmartScreen filter"),
    ("spoolsv.exe", "Print spooler"),
    ("searchindexer.exe", "Windows Search indexer"),
    ("searchhost.exe", "Windows Search UI"),
    ("shellexperiencehost.exe", "Shell experience"),
    ("shellhost.exe", "Shell host"),
    ("startmenuexperiencehost.exe", "Start menu"),
    ("textinputhost.exe", "Touch keyboard"),
    ("applicationframehost.exe", "App frame host"),
    ("backgroundtaskhost.exe", "Background task host"),
    ("wmiprvse.exe", "WMI provider host"),
    ("unsecapp.exe", "WMI callback sink"),
    ("dashost.exe", "Device association host"),
    ("wudfhost.exe", "User-mode driver host"),
    ("aggregatorhost.exe", "Sensor aggregator host"),
    ("msdtc.exe", "Distributed transactions"),
    ("mqsvc.exe", "Message Queuing"),
    ("wlanext.exe", "WLAN extensibility"),
    ("smsvchost.exe", ".NET port sharing"),
    ("monotificationux.exe", "Update notification"),
    ("systemsettings.exe", "Windows Settings"),
    ("phoneexperiencehost.exe", "Phone Link"),
    ("crossdeviceservice.exe", "Cross-device service"),
    ("crossdeviceresume.exe", "Cross-device resume"),
    ("widgetboard.exe", "Widgets board"),
    ("widgetservice.exe", "Widgets service"),
    ("appactions.exe", "App actions"),
    ("microsoftstartfeedprovider.exe", "MSN feed provider"),
    // --- Microsoft Defender ---
    ("msmpeng.exe", "Defender antivirus"),
    ("mpdefendercoreservice.exe", "Defender core service"),
    ("nissrv.exe", "Defender network inspection"),
    // --- shells / dev tooling ---
    ("cmd.exe", "Command Prompt"),
    ("powershell.exe", "Windows PowerShell"),
    ("pwsh.exe", "PowerShell"),
    ("windowsterminal.exe", "Windows Terminal"),
    ("bash.exe", "Git Bash"),
    ("sshd.exe", "OpenSSH server"),
    ("node.exe", "Node.js runtime"),
    ("electron.exe", "Electron app"),
    ("python.exe", "Python interpreter"),
    ("pythonw.exe", "Python (windowless)"),
    ("claude.exe", "Claude Code"),
    ("kev.exe", "kev monitor"),
    ("kev-monitor.exe", "kev launcher"),
    ("cli-proxy-api.exe", "CLI proxy API"),
    ("nssm.exe", "Service manager (NSSM)"),
    ("vctip.exe", "MSVC telemetry"),
    ("wslservice.exe", "WSL service"),
    ("updater.exe", "Application updater"),
    // --- browsers / comms ---
    ("chrome.exe", "Google Chrome"),
    ("msedge.exe", "Microsoft Edge"),
    ("msedgewebview2.exe", "Edge WebView2"),
    ("discord.exe", "Discord"),
    ("whatsapp.root.exe", "WhatsApp"),
    // --- databases / servers ---
    ("sqlservr.exe", "SQL Server"),
    ("sqlbrowser.exe", "SQL Browser"),
    ("sqlwriter.exe", "SQL VSS writer"),
    ("sqlceip.exe", "SQL telemetry"),
    ("mysqld.exe", "MySQL server"),
    // --- Office / Adobe ---
    ("officeclicktorun.exe", "Office updater"),
    ("sdxhelper.exe", "Office SDX helper"),
    ("seaport.exe", "Microsoft SeaPort"),
    ("adobecollabsync.exe", "Acrobat sync"),
    ("armsvc.exe", "Acrobat updater"),
    // --- Dell ---
    ("delloptimizer.exe", "Dell Optimizer"),
    ("dell.techhub.exe", "Dell TechHub"),
    ("dell.techhub.analytics.subagent.exe", "Dell analytics"),
    ("dell.techhub.datamanager.subagent.exe", "Dell data manager"),
    ("dell.techhub.diagnostics.subagent.exe", "Dell diagnostics"),
    ("dell.techhub.instrumentation.subagent.exe", "Dell instrumentation"),
    ("dell.techhub.instrumentation.userprocess.exe", "Dell instrumentation UI"),
    ("dell.connected.service.delivery.exe", "Dell service delivery"),
    ("dell.connected.service.delivery.subagent.exe", "Dell service delivery"),
    ("dell.coreservices.client.exe", "Dell core services"),
    ("dell.customer.connect.subagent.exe", "Dell customer connect"),
    ("dell.update.subagent.exe", "Dell update"),
    ("dellsupportassistremedationservice.exe", "Dell SupportAssist"),
    ("supportassistagent.exe", "Dell SupportAssist"),
    ("titancoresubagent.exe", "Dell component"),
    ("serviceshell.exe", "Dell SupportAssist UI"),
    // --- Intel ---
    ("igcc.exe", "Intel Graphics Center"),
    ("igcctray.exe", "Intel Graphics tray"),
    ("intelaudioservice.exe", "Intel audio service"),
    ("intelcphdcpsvc.exe", "Intel HDCP service"),
    ("intelgraphicssoftware.service.exe", "Intel graphics service"),
    ("ipf_helper.exe", "Intel platform helper"),
    ("ipf_uf.exe", "Intel platform service"),
    ("ipfsvc.exe", "Intel platform service"),
    ("jhi_service.exe", "Intel DAL host"),
    ("rstmwservice.exe", "Intel Rapid Storage"),
    ("presentmonservice.exe", "Intel PresentMon"),
    ("wmiregistrationservice.exe", "Intel ME WMI"),
    ("dphost.exe", "Intel DPHost"),
    ("izhost.exe", "Intel iZHost"),
    // --- audio vendors ---
    ("wavesaudioservice.exe", "Waves audio"),
    ("wavessyssvc64.exe", "Waves audio service"),
    ("audiodevmon.exe", "M-Audio monitor"),
    // --- networking / VPN ---
    ("tailscaled.exe", "Tailscale service"),
    ("tailscale-ipn.exe", "Tailscale client"),
    // --- licensing / vendor updaters ---
    ("fnplicensingservice64.exe", "FlexNet licensing"),
    ("nlssrv32.exe", "Nalpeiron licensing"),
    ("adsklicensingservice.exe", "Autodesk licensing"),
    ("adskaccessservicehost.exe", "Autodesk Access"),
    ("hpwuschd2.exe", "HP update scheduler"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(describe("SVCHOST.EXE"), Some("Windows service host"));
        assert_eq!(describe("svchost.exe"), Some("Windows service host"));
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(describe("totally-unknown-xyz.exe"), None);
    }

    #[test]
    fn no_duplicate_keys() {
        let mut keys: Vec<&str> = ENTRIES.iter().map(|(k, _)| *k).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate key in ENTRIES");
    }
}
