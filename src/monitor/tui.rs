//! Terminal UI over the monitor engine.
//!
//! `run` is the interactive full-screen app; `run_json` is a headless single-snapshot mode
//! (testable without a TTY; reusable by other frontends).
//!
//! The `Monitor` runs on a background thread and streams snapshots over a channel, so the UI
//! stays responsive even during the first (expensive) verification pass. Kill requests flow
//! back to the worker over a second channel.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Gauge, Paragraph, Row, Table, TableState};
use ratatui::{DefaultTerminal, Frame};

use crate::config::Config;
use crate::model::Verdict;
use crate::monitor::{LiveProcess, Monitor, Snapshot};

/// Headless: take two quick ticks (so CPU% is populated) and print one snapshot as JSON.
pub fn run_json(mut config: Config) -> anyhow::Result<()> {
    // Match the interactive monitor: offline verification for snappy, network-free ticks.
    config.signature.online_revocation = false;
    let mut monitor = Monitor::new(config);
    let _ = monitor.tick(usize::MAX);
    std::thread::sleep(Duration::from_millis(300));
    let snapshot = monitor.tick(usize::MAX);
    println!("{}", serde_json::to_string(&snapshot)?);
    Ok(())
}

const TICK: Duration = Duration::from_millis(1500);

enum ToWorker {
    Kill(u32),
    SetVtKey(String),
    /// User declined (or deferred) the first-launch VirusTotal prompt: persist a starter
    /// config so we don't ask again, leaving reputation disabled.
    DeclineVt,
    Stop,
}

enum FromWorker {
    Snap(Box<Snapshot>),
    Killed { pid: u32, name: String, ok: bool },
    KeySet { saved: bool },
}

/// Interactive TUI. `config_path` is where an in-app VirusTotal key update is persisted.
pub fn run(mut config: Config, config_path: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    // A live monitor must not do per-process network revocation every refresh; force offline
    // verification for snappy ticks (the one-shot `scan`/`verify` commands still honour config).
    config.signature.online_revocation = false;

    // First launch = no config file yet at the effective path. Either choice in the welcome
    // modal writes one, so the prompt appears exactly once.
    let effective_config = config_path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
    let first_run = !effective_config.exists();

    let (cmd_tx, cmd_rx) = mpsc::channel::<ToWorker>();
    let (evt_tx, evt_rx) = mpsc::channel::<FromWorker>();

    let worker = thread::spawn(move || worker_loop(config, config_path, cmd_rx, evt_tx));

    let mut terminal = ratatui::init();
    let result = ui_loop(&mut terminal, &evt_rx, &cmd_tx, first_run);
    ratatui::restore();

    let _ = cmd_tx.send(ToWorker::Stop);
    let _ = worker.join();
    result
}

/// How many not-yet-cached processes to verify per tick. Small enough that the first
/// snapshot (with resources + early verdicts) appears quickly; the rest fill in over a few
/// fast ticks.
const VERIFY_BUDGET: usize = 16;

/// Background thread: tick the monitor on an interval, service kill requests promptly. While
/// verdicts are still being computed it ticks rapidly so the table fills in fast; once caught
/// up it settles to the steady interval.
fn worker_loop(
    config: Config,
    config_path: Option<std::path::PathBuf>,
    cmd_rx: Receiver<ToWorker>,
    evt_tx: Sender<FromWorker>,
) {
    let mut monitor = Monitor::new(config);
    let mut last_tick = Instant::now()
        .checked_sub(TICK)
        .unwrap_or_else(Instant::now); // tick immediately
    let mut last_names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut pending = usize::MAX; // start in "filling in" mode

    loop {
        // Service commands first so kills feel immediate.
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                ToWorker::Stop => return,
                ToWorker::Kill(pid) => {
                    let ok = monitor.kill(pid);
                    let name = last_names.get(&pid).cloned().unwrap_or_default();
                    if evt_tx.send(FromWorker::Killed { pid, name, ok }).is_err() {
                        return;
                    }
                }
                ToWorker::SetVtKey(key) => {
                    let path = config_path
                        .clone()
                        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
                    let saved = crate::config::write_vt_key(&path, &key).is_ok();
                    monitor.set_vt_key(key);
                    if evt_tx.send(FromWorker::KeySet { saved }).is_err() {
                        return;
                    }
                }
                ToWorker::DeclineVt => {
                    let path = config_path
                        .clone()
                        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
                    let _ = crate::config::write_default_template(&path);
                }
            }
        }

        let interval = if pending > 0 { Duration::from_millis(120) } else { TICK };
        if last_tick.elapsed() >= interval {
            let snap = monitor.tick(VERIFY_BUDGET);
            pending = snap.pending;
            last_names = snap.processes.iter().map(|p| (p.pid, p.name.clone())).collect();
            if evt_tx.send(FromWorker::Snap(Box::new(snap))).is_err() {
                return;
            }
            last_tick = Instant::now();
        }
        thread::sleep(Duration::from_millis(40));
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Sort {
    Cpu,
    Mem,
    Net,
    Verdict,
    Pid,
    Name,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Sort::Cpu => Sort::Mem,
            Sort::Mem => Sort::Net,
            Sort::Net => Sort::Verdict,
            Sort::Verdict => Sort::Pid,
            Sort::Pid => Sort::Name,
            Sort::Name => Sort::Cpu,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Sort::Cpu => "CPU",
            Sort::Mem => "MEM",
            Sort::Net => "NET",
            Sort::Verdict => "VERDICT",
            Sort::Pid => "PID",
            Sort::Name => "NAME",
        }
    }
}

struct App {
    snapshot: Option<Snapshot>,
    state: TableState,
    sort: Sort,
    flagged_only: bool,
    confirm: Option<(u32, String)>,
    /// When `Some`, the VirusTotal-key input modal is open with this buffer.
    key_input: Option<String>,
    /// First-launch welcome modal offering to set up VirusTotal (optional).
    welcome: bool,
    status: String,
}

impl Default for App {
    fn default() -> Self {
        let mut state = TableState::default();
        state.select(Some(0));
        Self {
            snapshot: None,
            state,
            sort: Sort::Mem,
            flagged_only: false,
            confirm: None,
            key_input: None,
            welcome: false,
            status: "scanning… first pass verifies every process".into(),
        }
    }
}

impl App {
    /// `first_run` opens the one-time VirusTotal welcome modal.
    fn new(first_run: bool) -> Self {
        Self { welcome: first_run, ..Self::default() }
    }
}

enum Action {
    Continue,
    Quit,
}

impl App {
    /// Processes in current sort/filter order.
    fn view(&self) -> Vec<&LiveProcess> {
        let Some(snap) = &self.snapshot else {
            return vec![];
        };
        let mut v: Vec<&LiveProcess> = snap
            .processes
            .iter()
            .filter(|p| !self.flagged_only || is_flagged(p.verdict))
            .collect();
        match self.sort {
            Sort::Cpu => v.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent)),
            Sort::Mem => v.sort_by_key(|p| std::cmp::Reverse(p.memory_bytes)),
            Sort::Net => v.sort_by_key(|p| {
                std::cmp::Reverse(crate::collector::network::established_remote_count(&p.network))
            }),
            Sort::Verdict => v.sort_by_key(|p| std::cmp::Reverse(severity(p.verdict))),
            Sort::Pid => v.sort_by_key(|p| p.pid),
            Sort::Name => v.sort_by_key(|p| p.name.to_lowercase()),
        }
        v
    }

    fn selected_pid_name(&self) -> Option<(u32, String)> {
        let view = self.view();
        let i = self.state.selected()?;
        view.get(i).map(|p| (p.pid, p.name.clone()))
    }

    fn selected_proc(&self) -> Option<&LiveProcess> {
        self.view().get(self.state.selected()?).copied()
    }

    fn handle_key(&mut self, code: KeyCode, cmd_tx: &Sender<ToWorker>) -> Action {
        // First-launch welcome modal takes priority over everything.
        if self.welcome {
            match code {
                KeyCode::Enter => {
                    // Ensure a config file exists (records the choice), then open key entry.
                    self.welcome = false;
                    let _ = cmd_tx.send(ToWorker::DeclineVt);
                    self.key_input = Some(String::new());
                }
                KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Char('n') | KeyCode::Esc => {
                    self.welcome = false;
                    let _ = cmd_tx.send(ToWorker::DeclineVt);
                    self.status = "VirusTotal disabled — press v to add a key anytime".into();
                }
                _ => {} // modal: ignore other keys until the user chooses
            }
            return Action::Continue;
        }

        // Kill confirmation modal takes priority.
        if let Some((pid, name)) = self.confirm.clone() {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let _ = cmd_tx.send(ToWorker::Kill(pid));
                    self.status = format!("kill requested: {name} (pid {pid})");
                    self.confirm = None;
                }
                _ => {
                    self.status = "kill cancelled".into();
                    self.confirm = None;
                }
            }
            return Action::Continue;
        }

        // VirusTotal key entry modal takes priority too.
        if let Some(buf) = self.key_input.as_mut() {
            match code {
                KeyCode::Enter => {
                    let key = buf.trim().to_string();
                    self.key_input = None;
                    if key.is_empty() {
                        self.status = "VT key entry cancelled".into();
                    } else {
                        let _ = cmd_tx.send(ToWorker::SetVtKey(key));
                        self.status = "applying VirusTotal key…".into();
                    }
                }
                KeyCode::Esc => {
                    self.key_input = None;
                    self.status = "VT key entry cancelled".into();
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return Action::Continue;
        }

        let len = self.view().len();
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1, len),
            KeyCode::Up => self.move_sel(-1, len),
            KeyCode::PageDown => self.move_sel(10, len),
            KeyCode::PageUp => self.move_sel(-10, len),
            KeyCode::Char('s') => self.sort = self.sort.next(),
            KeyCode::Char('f') => self.flagged_only = !self.flagged_only,
            KeyCode::Char('v') => self.key_input = Some(String::new()),
            KeyCode::Char('k') => {
                if let Some((pid, name)) = self.selected_pid_name() {
                    self.confirm = Some((pid, name));
                }
            }
            KeyCode::Char('c') => {
                // Build owned data first so no `&self` borrow is alive when we set status.
                let prep = self.selected_proc().map(|p| {
                    let report = crate::investigate::build_report(p);
                    let dir = p
                        .image_path
                        .as_deref()
                        .and_then(|x| std::path::Path::new(x).parent())
                        .map(|d| d.to_string_lossy().into_owned());
                    (report, dir, format!("{} (pid {})", p.name, p.pid))
                });
                if let Some((report, dir, label)) = prep {
                    self.status = match crate::investigate::launch(&report, dir.as_deref()) {
                        Ok(()) => format!("opening Claude Code to investigate {label}…"),
                        Err(e) => format!("could not launch Claude Code: {e} — is `claude` installed?"),
                    };
                }
            }
            KeyCode::Char('a') => {
                // Bulk audit: every not-trusted, fully-verified process, worst-first.
                let prep = self.snapshot.as_ref().map(|snap| {
                    let mut tail: Vec<&LiveProcess> = snap
                        .processes
                        .iter()
                        .filter(|p| {
                            matches!(
                                p.verdict,
                                Some(Verdict::UnknownSigned)
                                    | Some(Verdict::Suspicious)
                                    | Some(Verdict::Malicious)
                            )
                        })
                        .collect();
                    tail.sort_by_key(|p| std::cmp::Reverse(severity(p.verdict)));
                    (crate::investigate::build_audit_report(&tail), tail.len())
                });
                if let Some((report, n)) = prep {
                    self.status = if n == 0 {
                        "audit: no unknown/suspect processes".into()
                    } else {
                        match crate::investigate::launch(&report, None) {
                            Ok(()) => format!("opening Claude Code to audit {n} unknown/suspect processes…"),
                            Err(e) => format!("could not launch Claude Code: {e} — is `claude` installed?"),
                        }
                    };
                }
            }
            _ => {}
        }
        Action::Continue
    }

    fn move_sel(&mut self, delta: i32, len: usize) {
        if len == 0 {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len as i32 - 1);
        self.state.select(Some(next as usize));
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Min(3),    // table
            Constraint::Length(5), // detail panel (selected process)
            Constraint::Length(1), // footer
        ])
        .split(f.area());

        self.render_header(f, chunks[0]);
        self.render_table(f, chunks[1]);
        self.render_detail(f, chunks[2]);
        self.render_footer(f, chunks[3]);

        if let Some((pid, name)) = self.confirm.clone() {
            self.render_confirm(f, &name, pid);
        }
        if let Some(buf) = self.key_input.clone() {
            self.render_key_input(f, &buf);
        }
        if self.welcome {
            self.render_welcome(f);
        }
    }

    /// One-time first-launch modal: explains kev works with no setup and offers optional
    /// VirusTotal enrichment (privacy-safe: only the SHA-256 is sent).
    fn render_welcome(&self, f: &mut Frame) {
        let area = centered_rect(74, 52, f.area());
        f.render_widget(Clear, area);
        let text = vec![
            Line::from(Span::styled(
                "Welcome to kev",
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("kev flags every running process as trusted / unknown / suspicious"),
            Line::from("from its signature, publisher, and behavior — no setup needed."),
            Line::from(""),
            Line::from("Optionally, it can cross-check unknown files against VirusTotal."),
            Line::from(Span::styled(
                "Only each file's SHA-256 is sent — never the file itself.",
                Style::new().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "Free key: https://www.virustotal.com/gui/my-apikey",
                Style::new().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "[Enter] add a VirusTotal key     [S / Esc] skip (add later with v)",
                Style::new().fg(Color::Yellow),
            )),
        ];
        let block = Block::bordered()
            .title(" first launch ")
            .border_style(Style::new().fg(Color::Cyan));
        f.render_widget(Paragraph::new(text).block(block).centered(), area);
    }

    /// Detail panel for the currently-selected row: full path, identity, and remotes (since the
    /// terminal has no hover).
    fn render_detail(&self, f: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" selected ");
        let view = self.view();
        let sel = self.state.selected().and_then(|i| view.get(i).copied());
        let lines: Vec<Line> = match sel {
            None => vec![Line::from(Span::styled("—", Style::new().fg(Color::DarkGray)))],
            Some(p) => {
                let head = format!(
                    "{} (pid {})   {}",
                    p.name,
                    p.pid,
                    p.image_path.as_deref().unwrap_or("—")
                );
                let mut id: Vec<String> = Vec::new();
                if let Some(v) = p.verdict {
                    id.push(format!("{v:?}"));
                }
                match (p.signed, p.publisher.as_deref()) {
                    (Some(true), Some(pubr)) => id.push(pubr.to_string()),
                    (Some(true), None) => id.push("signed".into()),
                    (Some(false), _) => id.push("unsigned".into()),
                    _ => {}
                }
                if let Some(t) = p.vt_total {
                    id.push(format!("VT {}/{}", p.vt_detections.unwrap_or(0), t));
                }
                if !p.fired_rules.is_empty() {
                    id.push(p.fired_rules.join(", "));
                }

                let mut rems: Vec<String> = p
                    .network
                    .iter()
                    .filter(|c| c.state == "Established" && crate::collector::network::is_remote(c))
                    .map(|c| format!("{}:{}", c.remote_addr, c.remote_port))
                    .collect();
                rems.sort();
                rems.dedup();
                let net = if rems.is_empty() {
                    "net: (no remote connections)".to_string()
                } else if rems.len() > 8 {
                    format!("net: {}  (+{} more)", rems[..8].join("  "), rems.len() - 8)
                } else {
                    format!("net: {}", rems.join("  "))
                };

                vec![
                    Line::from(head),
                    Line::from(Span::styled(id.join("  ·  "), Style::new().fg(Color::Gray))),
                    Line::from(Span::styled(net, Style::new().fg(Color::Cyan))),
                ]
            }
        };
        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let (cpu, mem_used, mem_total, count) = match &self.snapshot {
            Some(s) => (
                s.global.cpu_percent,
                s.global.mem_used,
                s.global.mem_total,
                s.global.process_count,
            ),
            None => (0.0, 0, 1, 0),
        };
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
        let cpu_ratio = (cpu / 100.0).clamp(0.0, 1.0) as f64;
        let mem_ratio = if mem_total > 0 {
            (mem_used as f64 / mem_total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let cpu_gauge = Gauge::default()
            .block(Block::bordered().title(format!("CPU  ({count} procs)")))
            .gauge_style(Style::new().fg(Color::Cyan))
            .ratio(cpu_ratio)
            .label(format!("{cpu:.0}%"));
        let mem_gauge = Gauge::default()
            .block(Block::bordered().title("MEM"))
            .gauge_style(Style::new().fg(Color::Magenta))
            .ratio(mem_ratio)
            .label(format!("{:.1}/{:.1} GB", gb(mem_used), gb(mem_total)));
        f.render_widget(cpu_gauge, cols[0]);
        f.render_widget(mem_gauge, cols[1]);
    }

    fn render_table(&mut self, f: &mut Frame, area: Rect) {
        let view = self.view();
        let rows: Vec<Row> = view
            .iter()
            .map(|p| {
                let color = verdict_color(p.verdict);
                Row::new(vec![
                    Cell::from(p.pid.to_string()),
                    Cell::from(truncate(&p.name, 20)),
                    Cell::from(truncate(p.description.as_deref().unwrap_or("—"), 26)),
                    Cell::from(truncate(p.user.as_deref().unwrap_or("-"), 14)),
                    Cell::from(format!("{:>5.1}", p.cpu_percent)),
                    Cell::from(format!("{:>7}", human_bytes(p.memory_bytes))),
                    Cell::from(net_cell(p)),
                    Cell::from(verdict_label(p.verdict)).style(Style::new().fg(color).bold()),
                    Cell::from(why(p)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(7),
            Constraint::Length(20),
            Constraint::Length(26),
            Constraint::Length(14),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(13),
            Constraint::Min(10),
        ];
        let header =
            Row::new(["PID", "NAME", "DESCRIPTION", "USER", "CPU%", "MEM", "NET", "VERDICT", "WHY"])
                .style(Style::new().bold().bg(Color::DarkGray));
        let title = format!(
            " processes — sort:{}{}  ",
            self.sort.label(),
            if self.flagged_only { "  [flagged-only]" } else { "" }
        );
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::bordered().title(title))
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");

        // Keep the selection valid: none when empty; top when it was cleared (e.g. while the
        // first snapshot loaded); clamped to the last row only if it ran past the end.
        let len = view.len();
        match self.state.selected() {
            _ if len == 0 => {
                self.state.select(None);
                *self.state.offset_mut() = 0;
            }
            None => {
                self.state.select(Some(0));
                *self.state.offset_mut() = 0;
            }
            Some(s) if s >= len => self.state.select(Some(len - 1)),
            _ => {}
        }
        f.render_stateful_widget(table, area, &mut self.state);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let keys = "↑↓ · [k]ill · [c]laude · [a]udit · [s]ort · [f]lagged · [v]t-key · [q]uit";
        let pending = self.snapshot.as_ref().map(|s| s.pending).unwrap_or(0);
        let status = if self.snapshot.is_none() {
            "starting…".to_string()
        } else if pending > 0 {
            format!("verifying… {pending} pending")
        } else {
            self.status.clone()
        };
        let line = Line::from(vec![
            Span::styled(keys, Style::new().fg(Color::Gray)),
            Span::raw("   "),
            Span::styled(status, Style::new().fg(Color::Yellow)),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn render_confirm(&self, f: &mut Frame, name: &str, pid: u32) {
        let area = centered_rect(60, 20, f.area());
        f.render_widget(Clear, area);
        let text = vec![
            Line::from(format!("Kill {name}  (pid {pid})?")),
            Line::from(""),
            Line::from(Span::styled(
                "[y] confirm    [n/Esc] cancel",
                Style::new().fg(Color::Yellow),
            )),
        ];
        let block = Block::bordered()
            .title(" confirm kill ")
            .border_style(Style::new().fg(Color::Red));
        f.render_widget(Paragraph::new(text).block(block).centered(), area);
    }

    fn render_key_input(&self, f: &mut Frame, buf: &str) {
        let area = centered_rect(70, 22, f.area());
        f.render_widget(Clear, area);
        // Mask all but the last 4 chars so a paste can be sanity-checked without exposing it.
        let masked: String = if buf.len() > 4 {
            "•".repeat(buf.len() - 4) + &buf[buf.len() - 4..]
        } else {
            "•".repeat(buf.len())
        };
        let text = vec![
            Line::from("Paste your VirusTotal API key, then Enter:"),
            Line::from(""),
            Line::from(Span::styled(
                format!("{masked}▏"),
                Style::new().fg(Color::Cyan),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "[Enter] save & apply    [Esc] cancel",
                Style::new().fg(Color::Yellow),
            )),
        ];
        let block = Block::bordered()
            .title(" VirusTotal key ")
            .border_style(Style::new().fg(Color::Cyan));
        f.render_widget(Paragraph::new(text).block(block).centered(), area);
    }
}

fn ui_loop(
    terminal: &mut DefaultTerminal,
    evt_rx: &Receiver<FromWorker>,
    cmd_tx: &Sender<ToWorker>,
    first_run: bool,
) -> anyhow::Result<()> {
    let mut app = App::new(first_run);
    loop {
        while let Ok(msg) = evt_rx.try_recv() {
            match msg {
                FromWorker::Snap(s) => app.snapshot = Some(*s),
                FromWorker::Killed { pid, name, ok } => {
                    app.status = if ok {
                        format!("killed {name} (pid {pid})")
                    } else {
                        format!("could not kill {name} (pid {pid}) — protected or access denied")
                    };
                }
                FromWorker::KeySet { saved } => {
                    app.status = if saved {
                        "VirusTotal key saved & applied".into()
                    } else {
                        "VirusTotal key applied (could not write config)".into()
                    };
                }
            }
        }
        terminal.draw(|f| app.render(f))?;
        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    if let Action::Quit = app.handle_key(k.code, cmd_tx) {
                        return Ok(());
                    }
                }
            }
        }
    }
}

// --- presentation helpers ---

fn is_flagged(v: Option<Verdict>) -> bool {
    matches!(v, Some(Verdict::Suspicious) | Some(Verdict::Malicious))
}

fn severity(v: Option<Verdict>) -> u8 {
    match v {
        Some(Verdict::Trusted) => 0,
        None => 1, // pending — sort near "unknown"
        Some(Verdict::UnknownSigned) => 1,
        Some(Verdict::Suspicious) => 2,
        Some(Verdict::Malicious) => 3,
    }
}

fn verdict_color(v: Option<Verdict>) -> Color {
    match v {
        Some(Verdict::Trusted) => Color::Green,
        Some(Verdict::UnknownSigned) => Color::Yellow,
        Some(Verdict::Suspicious) => Color::Rgb(255, 140, 0),
        Some(Verdict::Malicious) => Color::Red,
        None => Color::DarkGray,
    }
}

fn verdict_label(v: Option<Verdict>) -> &'static str {
    match v {
        Some(Verdict::Trusted) => "● Trusted",
        Some(Verdict::UnknownSigned) => "● Unknown",
        Some(Verdict::Suspicious) => "● Suspicious",
        Some(Verdict::Malicious) => "● MALICIOUS",
        None => "○ scanning…",
    }
}

/// Count of established off-box connections, e.g. "⇄3" (blank when none).
fn net_cell(p: &LiveProcess) -> String {
    let n = crate::collector::network::established_remote_count(&p.network);
    if n > 0 {
        format!("⇄{n}")
    } else {
        String::new()
    }
}

fn why(p: &LiveProcess) -> String {
    if p.verdict.is_none() {
        return "verifying…".into();
    }
    let mut parts: Vec<String> = Vec::new();
    if !p.fired_rules.is_empty() {
        parts.push(p.fired_rules.join(", "));
    } else {
        match (p.signed, p.publisher.as_deref()) {
            (Some(true), Some(pubr)) => parts.push(pubr.to_string()),
            (Some(true), None) => parts.push("signed".into()),
            (Some(false), _) => parts.push("unsigned".into()),
            (None, _) => {}
        }
    }
    if let Some(total) = p.vt_total {
        parts.push(format!("VT {}/{}", p.vt_detections.unwrap_or(0), total));
    }
    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(" · ")
    }
}

fn gb(bytes: u64) -> f64 {
    bytes as f64 / 1_000_000_000.0
}

fn human_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1}G", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{}M", bytes / 1_000_000)
    } else {
        format!("{}K", bytes / 1_000)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let v = Layout::vertical([Constraint::Percentage(percent_y)])
        .flex(Flex::Center)
        .split(area);
    Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .split(v[0])[0]
}
