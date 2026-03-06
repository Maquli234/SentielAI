# SentinelAI v2 — Advanced Recon Assistant

> ⚠ **FOR AUTHORIZED PENETRATION TESTING / EDUCATIONAL LAB ENVIRONMENTS ONLY.**
> Never test systems without explicit written permission.

---

## Overview

SentinelAI is a professional-grade terminal-based reconnaissance assistant. It combines Nmap scanning, automated analysis, CVE intelligence, exploit suggestions, web fingerprinting, subdomain enumeration, and optional AI-powered threat analysis into a single cohesive workflow.

**Core principle:** SentinelAI performs reconnaissance, analysis, and recommendations only. It never automatically exploits targets.

---

## Project Structure

```
sentinelai/
├── main.py                     Entry point; logging + DB init
├── cli.py                      Interactive terminal dashboard (prompt_toolkit + Rich)
├── scanner.py                  Nmap subprocess execution
├── parser.py                   Nmap XML → Python dataclasses
├── analyzer.py                 Risk scoring + pattern analysis
├── assistant.py                Rich output renderer + LLM integration
├── config.py                   Scan profiles, risk data, service KB
├── requirements.txt
│
├── modules/
│   ├── web_enum.py             HTTP header / technology fingerprinting
│   ├── subdomain_enum.py       DNS brute-force + CT log enumeration
│   ├── smb_enum.py             SMB script output analysis
│   └── ssh_analysis.py         SSH algorithm and version analysis
│
├── intelligence/
│   ├── cve_lookup.py           NVD NIST API CVE queries
│   └── exploit_advisor.py      Exploit reference database + suggestions
│
├── reporting/
│   └── report_generator.py     Markdown / HTML / JSON report generation
│
├── database/
│   └── db.py                   SQLite scan history (targets.db)
│
├── scans/                      Auto-saved Nmap XML + TXT output
├── reports/                    Generated reports
└── logs/                       sentinelai.log
```

---

## Installation

```bash
# Prerequisites
sudo apt update && sudo apt install nmap python3 python3-pip

# Clone / extract project
cd sentinelai/

# Install Python dependencies
pip install -r requirements.txt

# Run
python main.py
```

---

## Commands

### Scan Commands

| Command | Nmap Flags | Description |
|---|---|---|
| `scan <target>` | `-sS -sV -p-` | Full SYN + version scan |
| `quickscan <target>` | `-T4 -F` | Top 100 ports |
| `fullscan <target>` | `-sS -sV -p-` | All 65535 ports |
| `osscan <target>` | `-O` | OS fingerprinting |
| `vulnscan <target>` | `--script vuln` | NSE vulnerability scripts |
| `stealthscan <target>` | `-sS -Pn` | SYN, skip ping |
| `ports <target>` | `-sV --script default` | Service + default scripts |
| `webscan <target>` | `-p 80,443… --script http-*,ssl-*` | HTTP/HTTPS scripts |
| `smbscan <target>` | `-p 139,445 --script smb-*` | SMB enumeration |

### Enumeration & Intelligence

| Command | Description |
|---|---|
| `subdomains <domain>` | DNS brute-force + Certificate Transparency logs |
| `auto-recon <target>` | Full 4-step automated pipeline |

### Analysis & Reporting

| Command | Description |
|---|---|
| `analyze <xml_file>` | Parse and analyse a saved XML file |
| `report <xml_file> [--format md\|html\|json\|all]` | Generate security report |
| `history` | Show scan database history |
| `scans` | List saved XML scan files |

### Scan Options

```
--ports <range>     e.g. 1-1000 or 22,80,443
--speed <T0–T5>     Nmap timing template
--scripts <list>    Additional NSE scripts
--ai                Include LLM (Claude AI) analysis
--output <name>     Custom output filename
```

---

## Auto-Recon Pipeline

```
SentinelAI ❯ auto-recon 192.168.1.10 --ai
```

Runs 4 steps automatically:
1. Quick scan (port discovery)
2. Full scan (service detection)
3. Vulnerability scan (NSE scripts)
4. OS detection

Then renders a service graph and optional AI analysis.

---

## LLM Analysis (--ai flag)

When `--ai` is passed, SentinelAI sends sanitised scan metadata to Claude AI:
- Open ports, services, versions
- Risk findings
- OS fingerprint

Returns natural-language threat assessment and next steps.

**Requires:** `ANTHROPIC_API_KEY` environment variable set, or the tool running inside a Claude artifact context.

---

## Example CLI Session

```
╔═══════════════════════════════════════════════════╗
║   SENTINELAI  ADVANCED RECON ASSISTANT  v2.0.0    ║
╚═══════════════════════════════════════════════════╝

SentinelAI ❯ quickscan 192.168.1.10

╭──── INITIATING SCAN ──────────────────────────────╮
│ Target : 192.168.1.10                              │
│ Profile: Quick Scan                                │
│ Info   : Fast top-100 port recon                   │
╰────────────────────────────────────────────────────╯

⠹ Quick Scan…  [━━━━━━━━━━━━━━]  0:00:07

✓  Scan complete → scans/192.168.1.10_quick_20240601.xml

═══════════════════ SCAN ANALYSIS REPORT ═══════════════
  Time:    Mon Jun  1 14:30:22 2024
  Command: nmap -T4 -F -oX ...

╭── TARGET ──────────────────────────────────────────╮
│ 192.168.1.10  (metasploitable.local)               │
│ Risk: 8.6/10  CRITICAL                             │
╰────────────────────────────────────────────────────╯

OS:  ██████████  96%  Linux 2.6.x

                 Open Ports
PORT    PROTO  SERVICE    VERSION
21      tcp    ftp        vsftpd 2.3.4
22      tcp    ssh        OpenSSH 7.4
80      tcp    http       Apache httpd 2.2.8
139     tcp    netbios
445     tcp    smb        Samba 3.x
3306    tcp    mysql      MySQL 5.0.51a
5900    tcp    vnc

Risk Factors
  • CRITICAL risk port 445 (SMB)
  • CRITICAL risk port 5900 (VNC)
  • Outdated vsftpd 2.3.4
  • Outdated Samba 3.x

🔥  Potentially Vulnerable Versions
  [CRITICAL] Port 21  vsftpd 2.3.4 — backdoor CVE-2011-2523!
  [CRITICAL] Port 445 Samba 3.x — SambaCry CVE-2017-7494

╭────────────── SUGGESTED NEXT STEPS ────────────────────╮
│  • Test anonymous FTP login:                            │
│      ftp 192.168.1.10  (user: anonymous)               │
│                                                         │
│  • List SMB shares (null session):                      │
│      smbclient -L //192.168.1.10 -N                     │
│                                                         │
│  • Full SMB enumeration:                                │
│      enum4linux -a 192.168.1.10                         │
│                                                         │
│  • Check EternalBlue:                                   │
│      nmap --script smb-vuln-ms17-010 192.168.1.10       │
│                                                         │
│  • Connect MySQL (root, no pass):                       │
│      mysql -h 192.168.1.10 -u root                      │
│                                                         │
│  • Search exploits:                                     │
│      searchsploit vsftpd 2.3.4                          │
╰─────────────────────────────────────────────────────────╯

SentinelAI ❯ report scans/192.168.1.10_quick.xml --format all

✓  MARKDOWN report → reports/report_20240601.md
✓  JSON    report → reports/report_20240601.json
✓  HTML    report → reports/report_20240601.html
```

---

## Module Details

### `config.py`
Central data source — 9 scan profiles, 40 risky port definitions, 19 service knowledge base entries (with attack vectors and tool suggestions), 29 outdated version patterns.

### `scanner.py`
Wraps `subprocess.run(nmap …)` with a 15-minute timeout. Validates all inputs, saves XML + TXT output, returns structured result dict.

### `parser.py`
Pure XML parsing (no network I/O). Produces a hierarchy of typed dataclasses: `ScanResult → HostResult → PortInfo → ScriptResult`.

### `analyzer.py`
Pattern-matches ports/versions/scripts against config data. Produces `RiskyPort`, `OutdatedService`, `Finding` objects and a `RiskScore` (0–10). Includes an ASCII service graph generator.

### `assistant.py`
Rich-formatted output renderer. Handles host panels, port tables, OS progress bars, finding lists, and suggestion panels. Contains the optional LLM integration layer via the Anthropic API.

### `intelligence/cve_lookup.py`
Queries NVD NIST API v2 with rate-limit compliance (6s delay). Per-session caching to avoid duplicate requests. Returns `CVEEntry` objects with CVSS scores.

### `intelligence/exploit_advisor.py`
Local exploit reference database with 20+ service/version entries mapping to `searchsploit` queries and Metasploit module paths.

### `modules/web_enum.py`
HTTP header fetcher (no external tools). Audits 6 security headers (CSP, HSTS, etc.), fingerprints CMS (WordPress, Drupal, Joomla, etc.), extracts TLS certificate info.

### `modules/subdomain_enum.py`
Concurrent DNS resolution with configurable thread pool. Certificate Transparency log queries via `crt.sh`. Returns resolved IPs alongside each subdomain.

### `modules/smb_enum.py` & `ssh_analysis.py`
Parse Nmap NSE script output to surface SMB null sessions, EternalBlue status, SSH algorithm weaknesses, and password auth state.

### `database/db.py`
SQLite persistence for scan history, host summaries, port inventory, and findings. Enables the `history` command.

### `reporting/report_generator.py`
Generates Markdown, HTML (dark-themed), and JSON reports from `AnalysisReport` objects.

---

## Risk Scoring

Risk score is computed per-host from weighted factors:

| Factor | Weight |
|---|---|
| Critical risk port | 3.0 |
| High risk port | 2.0 |
| Medium risk port | 1.0 |
| Outdated version | 2.5 |
| CRITICAL outdated version | ×1.4 |
| NSE vulnerability script hit | 3.5 |
| Anonymous service detected | 2.0 |

Score is normalised to 0–10 and labelled: INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL.

---

## Legal Notice

SentinelAI is intended for:
- Authorized penetration testing engagements
- CTF / Capture The Flag competitions
- HackTheBox, TryHackMe, Metasploitable, DVWA, and similar lab environments
- Security education and research

**Unauthorised scanning is illegal in most jurisdictions.**
The authors accept no liability for misuse.
