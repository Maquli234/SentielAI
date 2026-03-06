# SentinelAI — Recon Assistant

> **FOR AUTHORIZED PENETRATION TESTING LAB ENVIRONMENTS ONLY.**
> Never use against systems you do not have explicit written permission to test.

---

## Overview

SentinelAI is a terminal-based reconnaissance assistant for ethical penetration testing labs.  
It wraps Nmap, parses XML results, analyses findings, and surfaces actionable next steps — but **never automatically exploits** anything.

---

## Project Structure

```
sentinelai/
├── main.py          Entry point; argument parsing; logging setup
├── cli.py           Interactive terminal dashboard (prompt_toolkit + Rich)
├── scanner.py       Nmap execution via subprocess; XML output management
├── parser.py        Nmap XML → Python dataclasses (hosts, ports, OS, scripts)
├── analyzer.py      Pattern-matching analysis; risky ports; outdated versions
├── assistant.py     Rich-formatted report renderer; suggested next steps
├── config.py        Scan profiles, risky port definitions, service suggestions
├── requirements.txt Python dependencies
├── scans/           Auto-created; stores .xml and .txt scan output
└── logs/            Auto-created; sentinelai.log
```

---

## Installation

### Prerequisites

- Python 3.11+
- Nmap installed and on your PATH

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install nmap python3 python3-pip

# Arch
sudo pacman -S nmap python python-pip

# macOS (Homebrew)
brew install nmap python
```

### Install Python dependencies

```bash
cd sentinelai/
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

Optional flags:

```bash
python main.py --log-level DEBUG    # verbose logging
python main.py --version            # print version
```

---

## Commands

| Command | Description |
|---|---|
| `scan <target>` | Full scan (SYN + version detection) |
| `quickscan <target>` | Fast top-100 port scan (`-T4 -F`) |
| `fullscan <target>` | All 65535 ports (`-sS -sV -p-`) |
| `osscan <target>` | OS fingerprinting (`-O`) |
| `vulnscan <target>` | NSE vulnerability scripts (`--script vuln`) |
| `stealthscan <target>` | SYN scan, skip ping (`-sS -Pn`) |
| `ports <target>` | Service + default scripts |
| `analyze <xml_file>` | Parse and analyse a saved XML file |
| `scans` | List saved scan files |
| `help` | Show help |
| `clear` | Clear screen |
| `exit` | Exit |

### Scan Options

All scan commands accept these optional flags:

```
--ports <range>       e.g.  1-1000  or  22,80,443
--speed <T0–T5>       Nmap timing template (T3 recommended for stealth)
--scripts <list>      Comma-separated NSE scripts
--output <name>       Custom output filename base
```

---

## Example CLI Session

```
╔══════════════════════════════════════════════════════╗
║         SENTINELAI RECON ASSISTANT  v1.0.0           ║
║         Educational use only                         ║
╚══════════════════════════════════════════════════════╝

⚠  FOR AUTHORIZED PENETRATION TESTING LAB ENVIRONMENTS ONLY.

SentinelAI ❯ quickscan 192.168.1.10

╭─────────── INITIATING SCAN ─────────────╮
│ Target : 192.168.1.10                   │
│ Profile: Quick Scan                     │
│ Info   : Fast top-100 port recon        │
╰─────────────────────────────────────────╯

⠹ Running Quick Scan…  [━━━━━━━━━━━━━━━━]  0:00:08

✓  Scan complete. Results saved → scans/192.168.1.10_quick_20240601_143022.xml

═══════════════════ SCAN ANALYSIS REPORT ═══════════════════
  Scan time : Mon Jun  1 14:30:22 2024
  Command   : nmap -T4 -F -oX ...

╭───────────────── TARGET HOST ─────────────────╮
│ 192.168.1.10  (metasploitable.local)           │
╰────────────────────────────────────────────────╯

                     Open Ports
PORT    PROTO  STATE  SERVICE    VERSION
21      tcp    open   ftp        vsftpd 2.3.4
22      tcp    open   ssh        OpenSSH 7.4
80      tcp    open   http       Apache httpd 2.2.8
139     tcp    open   netbios    Samba
445     tcp    open   microsoft  Samba
3306    tcp    open   mysql      MySQL 5.0.51a

⚠  Risky Ports Detected
  [HIGH]   21/tcp   FTP    — Check anonymous login; clear-text credentials
  [HIGH]   80/tcp   HTTP   — Directory brute-force; check for CVEs
  [HIGH]   445/tcp  SMB    — Enumerate shares; check EternalBlue (MS17-010)
  [HIGH]   3306/tcp MySQL  — Default credentials; check remote root

🔥  Potentially Vulnerable Services
  • Port 21  [ftp]   vsftpd 2.3.4
    vsftpd 2.3.4 — backdoor vulnerability (CVE-2011-2523)!
  • Port 80  [http]  Apache httpd 2.2.8
    Apache 2.2 — End-of-Life; many unpatched CVEs

╭──────────────── SUGGESTED NEXT STEPS ────────────────────╮
│                                                           │
│  • Test anonymous FTP login:                              │
│      ftp 192.168.1.10  (user: anonymous)                  │
│                                                           │
│  • Directory brute-force:                                 │
│      gobuster dir -u http://192.168.1.10 -w common.txt    │
│                                                           │
│  • Enumerate SMB shares:                                  │
│      smbclient -L //192.168.1.10 -N                       │
│                                                           │
│  • Check EternalBlue:                                     │
│      nmap --script smb-vuln-ms17-010 192.168.1.10         │
│                                                           │
│  • Connect to MySQL (root, no pass):                      │
│      mysql -h 192.168.1.10 -u root                        │
╰───────────────────────────────────────────────────────────╯

SentinelAI ❯ analyze scans/192.168.1.10_quick_20240601_143022.xml
```

---

## Scan Profiles Explained

| Profile | Nmap Flags | Notes |
|---|---|---|
| `quick` | `-T4 -F` | Top 100 ports, aggressive timing |
| `full` | `-sS -sV -p-` | All ports, SYN scan, version detection |
| `os` | `-O` | OS fingerprinting via TCP/IP stack analysis |
| `vuln` | `--script vuln` | NSE vulnerability detection scripts |
| `stealth` | `-sS -Pn` | SYN scan, skips ping (bypasses simple firewalls) |
| `ports` | `-sV --script default` | Service versions + default NSE scripts |

---

## Module Responsibilities

### `config.py`
Central data store: scan profiles, risky port definitions (21 port entries), service-to-suggestion mappings (16 services), and outdated version patterns (18 patterns). Edit here to customise risk scoring.

### `scanner.py`
Builds and executes the Nmap command via `subprocess.run()`. Handles timeouts (600 s hard cap), validates inputs, and returns a result dict with `success`, `xml_path`, `stdout`, and `stderr`.

### `parser.py`
Pure XML parsing — no network I/O. Produces `ScanResult → [HostResult] → [PortInfo]` dataclass trees. Also handles OS guesses and NSE script output.

### `analyzer.py`
Pattern matching against `config.py` data:
- Flags risky ports
- Detects outdated version strings
- Reads NSE script output for vulnerability indicators
- Scores hosts by risk and sorts them

### `assistant.py`
Rich-formatted output renderer. Converts `AnalysisReport` into coloured tables, progress bars, panels, and suggestion lists. Zero network I/O.

### `cli.py`
`prompt_toolkit` interactive loop with tab-completion, arrow-key history, and a `shlex`-based dispatcher. Orchestrates the scan → parse → analyse → render pipeline.

---

## Logging

All activity is logged to `logs/sentinelai.log`:

```
2024-06-01 14:30:10  INFO      sentinelai.main     Starting SentinelAI v1.0.0
2024-06-01 14:30:22  INFO      sentinelai.scanner  Running: nmap -T4 -F -oX ...
2024-06-01 14:30:31  DEBUG     sentinelai.parser   Parsed 1 host(s) from file.xml
2024-06-01 14:30:31  DEBUG     sentinelai.analyzer Host 192.168.1.10: 4 risky ports ...
```

---

## Legal Notice

SentinelAI is designed for **educational use in controlled lab environments** (e.g. HackTheBox, TryHackMe, DVWA, Metasploitable).

- **Always** obtain written permission before scanning any system.
- Unauthorised scanning is illegal in most jurisdictions.
- The authors accept no liability for misuse.
