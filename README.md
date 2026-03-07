<div align="center">

# 🛡️ SentinelAI

**AI-Assisted Reconnaissance & Intelligence Framework for Penetration Testers**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)](https://github.com/USERNAME/sentinelai)
[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/USERNAME/sentinelai)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Automate reconnaissance. Correlate intelligence. Surface what matters.*

</div>

---

## Overview

**SentinelAI** is an open-source AI-assisted reconnaissance and intelligence framework designed to help penetration testers automate and accelerate the reconnaissance and enumeration phases of security assessments.

SentinelAI acts as both an **orchestrator for industry-standard security tools** and an **AI-powered analysis engine** that transforms raw scan output into structured, actionable penetration testing intelligence. Rather than replacing human judgment, SentinelAI amplifies it — surfacing critical findings, correlating vulnerabilities, scoring attack surfaces, and recommending targeted next steps.

```
[ Target ] ──► [ Automated Recon ] ──► [ Vulnerability Intel ] ──► [ Risk Scoring ] ──► [ Report ]
```

---

## Key Features

- **Automated Reconnaissance** — Full port scanning, service detection, OS fingerprinting, and NSE script execution
- **Enumeration Assistance** — HTTP, SMB, FTP, SSH, and subdomain enumeration modules
- **Vulnerability Intelligence** — CVE correlation, exploit references, and severity mapping
- **Attack Surface Scoring** — Risk scoring engine with ranked findings and justifications
- **Recon Pipeline Automation** — End-to-end automated pipeline from discovery through report generation
- **Tool Orchestration** — Integrates with Nmap, Gobuster, ffuf, Nikto, Amass, and more
- **AI-Assisted Analysis** — Optional LLM-powered analysis for recommended penetration testing paths
- **Self-Learning Intelligence** — Historical scan data storage to improve recommendations over time

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Usage](#usage)
- [Core Modules](#core-modules)
- [Attack Surface Scoring](#attack-surface-scoring)
- [Recon Pipeline](#recon-pipeline)
- [Tool Integration](#tool-integration)
- [AI-Assisted Analysis](#ai-assisted-analysis)
- [Self-Learning Intelligence](#self-learning-intelligence)
- [Reporting](#reporting)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Security Disclaimer](#security-disclaimer)
- [License](#license)

---

## Installation

> **Requirements:** Python 3.9+, Linux or macOS. Dependent tools (Nmap, Gobuster, etc.) must be installed separately.

### Clone the Repository

```bash
git clone https://github.com/USERNAME/sentinelai.git
cd sentinelai
```

### Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### Verify Installation

```bash
sentinelai --help
```

---

## Usage

### Basic Commands

```bash
# Full recon scan against a single IP
sentinelai scan 192.168.1.10

# Automated external recon against a domain
sentinelai autorecon target.com

# Web-focused scan (HTTP enumeration, tech fingerprinting, vuln checks)
sentinelai webscan target.com

# Generate a report from a completed scan session
sentinelai report target.com
```

### Example Output

```
[*] SentinelAI v1.0.0 | Starting reconnaissance against 192.168.1.10
[+] Running full port scan ............................................. done
[+] Service detection complete ......................................... done
[+] OS fingerprinting .................................................. done
[+] Running NSE vulnerability scripts ................................. done
[+] Enumerating HTTP on port 80 ........................................ done
[+] Enumerating SMB shares ............................................ done
[+] Checking FTP anonymous access ..................................... found
[+] Looking up CVEs for detected services ............................. 4 found
[+] Correlating vulnerability intelligence ............................. done
[+] Calculating attack surface risk score .............................. 8.1 / 10
[+] Generating HTML and PDF report .................................... done

[!] Critical findings: 2 | High: 3 | Medium: 1
[*] Report saved to: ./reports/192.168.1.10_20240315_143021/
```

### Additional Options

```bash
# Set scan intensity (1=stealth, 3=default, 5=aggressive)
sentinelai scan 10.0.0.1 --intensity 2

# Limit modules to run
sentinelai scan 10.0.0.1 --modules nmap,http,smb

# Specify output format
sentinelai report target.com --format pdf

# Enable AI analysis (requires API key configuration)
sentinelai autorecon target.com --ai

# View scan history
sentinelai history list
```

---

## Core Modules

### Automated Reconnaissance

SentinelAI performs multi-phase port and service discovery using Nmap as its primary scanning engine.

| Phase | Description |
|---|---|
| Full Port Scan | TCP/UDP scan across all 65,535 ports |
| Service Detection | Banner grabbing and service version identification |
| OS Fingerprinting | TCP/IP stack analysis for OS detection |
| NSE Script Scanning | Targeted Nmap Scripting Engine scripts for vulnerability detection |

```bash
sentinelai scan 10.10.10.5 --modules nmap
```

### Enumeration Assistance

Once services are detected, SentinelAI launches targeted enumeration modules appropriate for the identified attack surface:

**HTTP Enumeration**
Directory and file brute-forcing, technology fingerprinting, header analysis, and common vulnerability checks via Gobuster, ffuf, Nikto, and WhatWeb.

**SMB Analysis**
Share enumeration, null session testing, version detection, and known SMB vulnerability checks via enum4linux and CrackMapExec-compatible modules.

**FTP Security Checks**
Anonymous access detection, banner grabbing, permission analysis, and CVE correlation for detected FTP services.

**SSH Configuration Analysis**
Algorithm enumeration, key exchange inspection, weak configuration detection, and version-based vulnerability identification.

**Subdomain Discovery**
Passive and active subdomain enumeration via Amass and Subfinder, with DNS resolution and live host validation.

---

## Attack Surface Scoring

SentinelAI calculates a **composite risk score** for each target based on the severity and combination of detected findings. Scores are weighted by exploitability, exposure, and business impact potential.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Attack Surface Risk Score: 8.1 / 10
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Contributing Factors:
  ✖  Exposed SMB (port 445) — publicly accessible
  ✖  Outdated Apache 2.4.29 — CVE-2021-41773 applicable
  ✖  Anonymous FTP access enabled
  ✖  Weak TLS configuration (TLS 1.0 enabled, RC4 cipher)

  Score Breakdown:
  ├── Network Exposure:      9.0 / 10
  ├── Service Vulnerabilities: 8.5 / 10
  ├── Configuration Weaknesses: 7.8 / 10
  └── Patch Posture:         7.2 / 10
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Recon Pipeline

SentinelAI can execute a full, automated reconnaissance pipeline with a single command. Each stage feeds into the next, allowing scan results to inform subsequent modules.

```bash
sentinelai autorecon target.com
```

**Pipeline Stages:**

```
Stage 1 │ Port Scan            → Discover open ports across TCP/UDP
Stage 2 │ Service Detection    → Identify services and version strings
Stage 3 │ Vulnerability Scripts→ Run NSE scripts for known vulnerabilities
Stage 4 │ Service Enumeration  → Launch targeted enumeration per service
Stage 5 │ Vulnerability Intel  → Correlate CVEs and exploit references
Stage 6 │ Risk Scoring         → Calculate weighted attack surface score
Stage 7 │ Report Generation    → Produce structured findings report
```

Stages can be individually enabled, disabled, or re-ordered via configuration. Parallel execution is supported where stage dependencies allow.

---

## Tool Integration

SentinelAI orchestrates a suite of best-in-class open-source security tools. It handles invocation, output parsing, and cross-tool result correlation automatically.

| Tool | Purpose |
|---|---|
| [Nmap](https://nmap.org/) | Port scanning, service detection, NSE scripts |
| [Gobuster](https://github.com/OJ/gobuster) | Directory and DNS brute-forcing |
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzing and content discovery |
| [Nikto](https://github.com/sullo/nikto) | Web server vulnerability scanning |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Web technology fingerprinting |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) | SMB and NetBIOS enumeration |
| [Amass](https://github.com/owasp-amass/amass) | Subdomain enumeration and DNS mapping |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery |

Results from each tool are parsed into a normalized internal schema, deduplicated, and correlated to produce a unified picture of the target's attack surface.

---

## AI-Assisted Analysis

SentinelAI can optionally leverage an LLM backend to perform reasoning-layer analysis on scan results. When enabled, the AI module:

- Interprets detected services and configurations in the context of real-world penetration testing engagements
- Identifies logical attack chains across multiple findings
- Recommends targeted follow-up techniques, tools, and payloads based on the identified attack surface
- Flags unusual or noteworthy findings that rule-based engines may miss
- Generates plain-language summaries suitable for inclusion in client-facing reports

```bash
# Enable AI analysis (configure API key in ~/.sentinelai/config.yaml)
sentinelai autorecon target.com --ai
sentinelai analyze ./reports/target.com_latest/ --ai --depth thorough
```

AI analysis is entirely **optional and opt-in**. SentinelAI is fully functional without an LLM backend configured.

---

## Self-Learning Intelligence

SentinelAI includes a local intelligence layer that stores and indexes scan history. Over time, this enables:

- **Trend analysis** — Track how a target's attack surface changes between assessments
- **Baseline comparison** — Automatically highlight new findings relative to prior scans
- **Recommendation tuning** — Weight enumeration suggestions based on historically productive techniques for similar service profiles
- **Environment pattern recognition** — Identify recurring misconfigurations or technology stacks across engagements

All data is stored locally in a structured SQLite database and never transmitted externally.

```bash
# View historical scans for a target
sentinelai history show target.com

# Compare two scan sessions
sentinelai diff target.com --from 2024-01-10 --to 2024-03-15
```

---

## Reporting

SentinelAI generates professional, structured reports from completed scan sessions.

### Supported Formats

| Format | Use Case |
|---|---|
| HTML | Interactive browser-based report with collapsible sections |
| PDF | Client-ready report for formal deliverables |
| Markdown | Version-control-friendly format for internal documentation |
| JSON | Machine-readable output for pipeline integration and tooling |

### Report Contents

Every report includes:

- **Executive Summary** — Risk score, critical finding count, and high-level assessment
- **Open Ports & Services** — Detailed table of discovered ports with version and banner data
- **Vulnerability Findings** — CVE IDs, CVSS scores, exploit references, and remediation notes
- **Configuration Weaknesses** — Service-level misconfigurations and hardening recommendations
- **Attack Surface Risk Score** — Weighted score with contributing factor breakdown
- **Recommended Testing Steps** — Prioritized list of follow-up penetration testing actions

```bash
# Generate report for a completed scan
sentinelai report target.com --format html
sentinelai report target.com --format pdf --output ./deliverables/
```

---

## Project Structure

```
sentinelai/
├── sentinelai/
│   ├── __init__.py
│   ├── cli.py                  # CLI entry point and argument parsing
│   ├── core/
│   │   ├── scanner.py          # Port scanning and service detection
│   │   ├── pipeline.py         # Automated recon pipeline orchestration
│   │   └── orchestrator.py     # Tool invocation and output normalization
│   ├── modules/
│   │   ├── http.py             # HTTP enumeration module
│   │   ├── smb.py              # SMB analysis module
│   │   ├── ftp.py              # FTP security checks
│   │   ├── ssh.py              # SSH configuration analysis
│   │   └── subdomain.py        # Subdomain discovery module
│   ├── intelligence/
│   │   ├── cve.py              # CVE lookup and correlation
│   │   ├── scoring.py          # Attack surface risk scoring engine
│   │   └── ai_analysis.py      # LLM-assisted analysis layer
│   ├── reporting/
│   │   ├── html.py             # HTML report generator
│   │   ├── pdf.py              # PDF report generator
│   │   ├── markdown.py         # Markdown report generator
│   │   └── json_export.py      # JSON export module
│   └── database/
│       ├── models.py           # Database schema and ORM models
│       ├── store.py            # Scan data persistence layer
│       └── history.py          # Historical intelligence and diff engine
├── tests/
│   ├── unit/
│   └── integration/
├── docs/
│   ├── configuration.md
│   ├── modules.md
│   └── api.md
├── config/
│   └── default.yaml            # Default configuration template
├── requirements.txt
├── setup.py
└── README.md
```

---

## Roadmap

SentinelAI is under active development. Planned improvements include:

**v1.1**
- Reconnaissance dashboard — Web-based UI for managing scans, reviewing findings, and tracking targets over time
- Distributed scanning agents — Deploy lightweight scan agents across multiple hosts for broader coverage

**v1.2**
- Enhanced AI reasoning — Multi-step chain-of-thought analysis for complex attack surface scenarios
- Plugin marketplace — Community-developed modules for specialized recon use cases

**Future**
- Vulnerability intelligence enrichment — Integration with additional threat intelligence feeds (NVD, ExploitDB, VulnDB)
- CI/CD pipeline mode — Headless operation for integration into automated security testing workflows
- MITRE ATT&CK mapping — Map findings to ATT&CK techniques and tactics for structured threat modeling

---

## Security Disclaimer

> ⚠️ **Authorized Use Only**

SentinelAI is designed exclusively for:

- **Authorized penetration testing** — Use only on systems and networks for which you have explicit written permission
- **Security research** — In controlled lab environments or responsible disclosure contexts
- **Educational purposes** — Learning reconnaissance techniques in isolated, legal environments

**Unauthorized use of SentinelAI against systems you do not own or have explicit permission to test is illegal and unethical.** The authors accept no liability for misuse of this tool. Users are solely responsible for ensuring their activities comply with all applicable local, national, and international laws.

If you are unsure whether your use is authorized, it is not.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests. For significant changes, open an issue first to discuss the proposed modification.

```bash
# Run the test suite
pytest tests/ -v

# Run linting
flake8 sentinelai/
black sentinelai/ --check
```

---

## License

```
MIT License

Copyright (c) 2024 SentinelAI Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

Built for the security community. Use responsibly.

</div>
