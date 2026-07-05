# kev

**A live Windows process-legitimacy monitor.** kev looks at every process running on your
machine, decides whether it's trustworthy, and shows you the answer as a color-coded, sortable
table — like Task Manager, but the columns are *"is this thing supposed to be here?"* instead of
just CPU and memory.

It was built after a real cryptojacking incident, to answer one question fast: **which of these
processes don't belong?**

```
 CPU  (312 procs)                          MEM  23.9G / 31.8G
┌───────────────────────────────────────────────────────────────────────────┐
│ PID    NAME              VERDICT        NET   CPU   MEM    WHY               │
│ 1234   svchost.exe       ● Trusted            0.1%  38M    Microsoft Windows │
│ 9012   chrome.exe        ● Trusted      ⇄7    4.2%  512M   Google LLC        │
│ 7788   MyLittleTool.exe  ● Unknown            0.0%  12M    unsigned          │
│ 4455   updat3r.exe       ● Suspicious   ⇄2    1.1%  8M     name_spoof, ...   │
│ 6620   xmr-stak.exe      ● MALICIOUS    ⇄3   98.0%  2.1G   VT 58/72          │
└───────────────────────────────────────────────────────────────────────────┘
 ↑↓ · [k]ill · [c]laude · [a]udit · [s]ort · [f]lagged · [v]t-key · [q]uit
```

---

## What it does

For every running process, kev:

1. **Enumerates** it (name, PID, image path, parent, owning user, CPU/mem, network connections).
2. **Verifies its Authenticode signature** — both embedded and catalog-signed (the way most
   Windows system binaries are signed) — via `WinVerifyTrust`, and extracts the signing publisher.
3. **Hashes** the untrusted ones (SHA-256) — trusted-publisher binaries skip hashing for speed.
4. **Runs masquerade heuristics** — wrong path, wrong parent, name-spoofing (homoglyph/typo of a
   system binary), unsigned binary in a system directory, untrusted publisher in a system directory.
5. *(optional)* **Cross-checks unknown files against VirusTotal** — by hash only.
6. **Scores** all of that into one of four verdicts and colors the row.

Then you can **sort**, **filter to flagged only**, **kill** a process, or hand its full forensic
profile to **Claude Code** for a deeper investigation.

## The verdict model

| Verdict | Color | Meaning |
|---|---|---|
| **Trusted** | 🟢 green | Validly signed by a trusted publisher (or a known-good baseline / OS kernel pseudo-process). |
| **Unknown** | 🟡 yellow | Signed, but by a publisher kev doesn't vouch for — or simply unrecognized. Not evidence of malice. |
| **Suspicious** | 🟠 orange | Something is off: unsigned in a system path, masquerading as a system binary, broken/ revoked chain, etc. |
| **Malicious** | 🔴 red | Strong signal — e.g. an unsigned binary spoofing a system process, or a VirusTotal detection over threshold. |

The main path to green is **publisher trust**: a validly-signed binary whose publisher matches a
trusted vendor (Microsoft, Google, Intel, NVIDIA, …) is trusted without needing a per-machine
baseline. See [`config.example.toml`](config.example.toml) to tune the trusted-publisher list,
rule weights, and score thresholds.

## Install

**Requirements:** Windows 10/11 (x64) and a recent Rust toolchain (1.94+).

```powershell
git clone https://github.com/loughraieb/kev-monitor
cd kev-monitor

# Build a portable, statically-linked release (no VC++ redistributable needed):
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release --features reputation
```

This produces two binaries (in your Cargo target dir):

- **`kev.exe`** — the tool itself (`kev monitor`, `kev scan`, `kev verify`, `kev baseline`).
- **`kev-monitor.exe`** — a clickable launcher that self-elevates via UAC and opens the monitor in
  Windows Terminal. Keep it next to `kev.exe`.

Drop `kev.exe` + `kev-monitor.exe` in a folder, and you're done — no installer. The only DLLs it
imports (`kernel32`, `ntdll`, `advapi32`, `crypt32`, `wintrust`, `ws2_32`, `bcrypt`, …) ship with
Windows; SQLite is compiled in.

> Build without `--features reputation` to drop the VirusTotal integration (and the `ureq`
> HTTP dependency) entirely.

## Usage

Double-click **`kev-monitor.exe`** (approves a UAC prompt for full visibility), or run:

```powershell
kev monitor
```

Running **elevated** is recommended — without admin, image paths and hashes of SYSTEM-owned
processes may be unreadable, degrading coverage.

### Keys

| Key | Action |
|---|---|
| `↑` / `↓` / `j` | Move selection |
| `PgUp` / `PgDn` | Jump 10 rows |
| `s` | Cycle sort: CPU → MEM → NET → VERDICT → PID → NAME |
| `f` | Toggle "flagged only" (Suspicious + Malicious) |
| `k` | Kill the selected process (with confirmation) |
| `c` | **Investigate** the selected process with Claude Code |
| `a` | **Audit** all unknown/suspect processes with Claude Code |
| `v` | Enter/update a VirusTotal API key |
| `q` / `Esc` | Quit |

### Other commands

```powershell
kev scan --pretty                 # one-shot: JSON verdict for every process
kev verify --pid 1234             # deep-check a single process
kev verify --path C:\x\y.exe      # deep-check a file on disk
kev baseline                      # record this (clean) machine's binaries as known-good
kev monitor --json                # headless: print one JSON snapshot
```

## VirusTotal (optional)

kev works fully without VirusTotal. If you want the extra signal:

- On **first launch** the monitor offers to add a key — or skip (you can add one anytime with `v`).
- Get a free key at <https://www.virustotal.com/gui/my-apikey>.
- **Privacy:** kev only ever sends a file's **SHA-256 hash** to VirusTotal — never the file, path,
  or any other data. Results are cached locally (SQLite) and rate-limited to respect the free tier.

Your key is written to a local `config.toml` next to the binary. **That file is gitignored and
must never be committed.**

## Investigate with Claude Code

If you have [Claude Code](https://claude.com/claude-code) (`claude`) on your PATH, press `c` (one
process) or `a` (all unknown/suspect processes). kev writes a forensic report — signature,
publisher, hash, parent, network connections, fired heuristics, VirusTotal result — to a temp
file and opens a new terminal running `claude`, seeded to investigate it. The report explicitly
tells the agent to analyze statically and treat the file's contents as untrusted data.

## How it decides (in short)

- **Signature & publisher** are the backbone: catalog + embedded Authenticode via `WinVerifyTrust`,
  publisher pulled from the trust chain. Trusted publisher ⇒ green, no baseline required.
- **Heuristics** catch impersonation that a signature can't: a binary named `svcʜost.exe` in
  `%TEMP%`, an unsigned `lsass.exe`, a "svchost" whose parent isn't `services.exe`, etc. These are
  suppressed when a binary is validly signed by a trusted publisher, to avoid false positives on
  legitimately-signed OS components.
- **Scoring** sums rule weights and applies thresholds (both configurable) to pick the verdict.

## Privacy & safety

- **Local-first.** Everything runs on your machine. The only outbound network call is the optional
  VirusTotal hash lookup, and only when you've enabled it.
- **No telemetry.** kev phones home to nothing.
- **Killing is real.** `k` terminates the process; kev asks for confirmation first. Some protected
  processes can't be killed even elevated.

## Limitations

- **Windows x64 only** — it relies on Windows-native APIs (WinTrust, catalog signing). It won't run
  on Linux/macOS; on ARM64 Windows it runs under x64 emulation.
- Publisher trust is substring-based and intentionally conservative; tune the list to your fleet.
- Heuristics are deliberately simple and explainable, not an EDR. kev is a fast triage lens, not a
  replacement for a full endpoint-protection product.

## License

MIT — see [LICENSE](LICENSE).
