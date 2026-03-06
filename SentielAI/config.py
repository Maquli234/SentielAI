"""
SentinelAI Configuration Module
================================
Central configuration for scan profiles, risky ports, and service rules.
FOR AUTHORIZED LAB USE ONLY.
"""

import os
from pathlib import Path

# ── Directories ──────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
SCANS_DIR  = BASE_DIR / "scans"
LOGS_DIR   = BASE_DIR / "logs"

SCANS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ── Tool identity ─────────────────────────────────────────────────────────────
TOOL_NAME    = "SentinelAI"
TOOL_VERSION = "1.0.0"
DISCLAIMER   = (
    "⚠  FOR AUTHORIZED PENETRATION TESTING LAB ENVIRONMENTS ONLY.\n"
    "   Never use against systems you do not have explicit written permission to test."
)

# ── Nmap scan profiles ────────────────────────────────────────────────────────
# Each profile maps to an nmap argument list (target is appended at runtime).
SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "label": "Quick Scan",
        "description": "Fast top-100 port reconnaissance",
        "args": [
            "-T4",   # Aggressive timing (faster)
            "-F",    # Fast mode — scan only top 100 ports
        ],
    },
    "full": {
        "label": "Full Scan",
        "description": "All 65535 ports + service/version detection",
        "args": [
            "-sS",   # SYN (stealth) scan — half-open, less noisy
            "-sV",   # Probe open ports to detect service/version
            "-p-",   # Scan ALL ports (1–65535)
        ],
    },
    "os": {
        "label": "OS Detection Scan",
        "description": "Detect operating system via TCP/IP fingerprinting",
        "args": [
            "-O",    # Enable OS detection
        ],
    },
    "vuln": {
        "label": "Vulnerability Scan",
        "description": "Run nmap's built-in vuln NSE scripts",
        "args": [
            "--script", "vuln",   # Execute vulnerability detection scripts
        ],
    },
    "stealth": {
        "label": "Stealth Scan",
        "description": "SYN scan with no ping (evades simple firewalls)",
        "args": [
            "-sS",   # SYN scan
            "-Pn",   # Skip host discovery (treat host as up)
        ],
    },
    "ports": {
        "label": "Service Scan",
        "description": "Version + script detection on common ports",
        "args": [
            "-sV",            # Service/version detection
            "--script",
            "default",        # Run default NSE scripts
        ],
    },
}

# ── Speed / timing templates ──────────────────────────────────────────────────
# nmap -T0 (paranoid) … -T5 (insane)
VALID_SPEEDS = {"T0", "T1", "T2", "T3", "T4", "T5"}

# ── Risky / interesting ports ─────────────────────────────────────────────────
RISKY_PORTS: dict[int, dict] = {
    21:   {"service": "FTP",       "risk": "HIGH",   "note": "Check anonymous login; clear-text credentials"},
    22:   {"service": "SSH",       "risk": "MEDIUM", "note": "Check weak/default credentials; key-auth brute-force"},
    23:   {"service": "Telnet",    "risk": "HIGH",   "note": "Clear-text protocol; credentials sniffable"},
    25:   {"service": "SMTP",      "risk": "MEDIUM", "note": "Check open relay; user enumeration (VRFY/EXPN)"},
    53:   {"service": "DNS",       "risk": "MEDIUM", "note": "Test zone transfer (AXFR)"},
    80:   {"service": "HTTP",      "risk": "MEDIUM", "note": "Directory brute-force; check for CVEs"},
    110:  {"service": "POP3",      "risk": "MEDIUM", "note": "Clear-text; credential brute-force"},
    111:  {"service": "RPCBind",   "risk": "HIGH",   "note": "Enumerate NFS exports"},
    135:  {"service": "MSRPC",     "risk": "HIGH",   "note": "Windows RPC; potential lateral movement"},
    139:  {"service": "NetBIOS",   "risk": "HIGH",   "note": "SMB/NetBIOS; enumerate shares & users"},
    143:  {"service": "IMAP",      "risk": "MEDIUM", "note": "Clear-text; credential brute-force"},
    443:  {"service": "HTTPS",     "risk": "MEDIUM", "note": "Check TLS version, certs, web app vulnerabilities"},
    445:  {"service": "SMB",       "risk": "HIGH",   "note": "Enumerate shares; check EternalBlue (MS17-010)"},
    512:  {"service": "rexec",     "risk": "HIGH",   "note": "Legacy remote exec; often exploitable"},
    513:  {"service": "rlogin",    "risk": "HIGH",   "note": "Clear-text remote login"},
    514:  {"service": "rsh",       "risk": "HIGH",   "note": "Remote shell; no authentication"},
    1521: {"service": "Oracle DB", "risk": "HIGH",   "note": "Default credentials; TNS poisoning"},
    2049: {"service": "NFS",       "risk": "HIGH",   "note": "Mount & read exposed NFS shares"},
    3306: {"service": "MySQL",     "risk": "HIGH",   "note": "Default credentials; check remote root"},
    3389: {"service": "RDP",       "risk": "HIGH",   "note": "BlueKeep check; brute-force credentials"},
    5432: {"service": "PostgreSQL","risk": "HIGH",   "note": "Default credentials; check trust auth"},
    5900: {"service": "VNC",       "risk": "HIGH",   "note": "Check no-auth mode; brute-force"},
    6379: {"service": "Redis",     "risk": "HIGH",   "note": "Unauthenticated access; config dump"},
    8080: {"service": "HTTP-alt",  "risk": "MEDIUM", "note": "Admin panels; web app vulnerabilities"},
    8443: {"service": "HTTPS-alt", "risk": "MEDIUM", "note": "Admin panels; check certificates"},
    27017:{"service": "MongoDB",   "risk": "HIGH",   "note": "Check unauthenticated access"},
}

# ── Service-to-suggestion mapping ─────────────────────────────────────────────
SERVICE_SUGGESTIONS: dict[str, list[str]] = {
    "ftp": [
        "Test anonymous FTP login:  ftp <target>  (user: anonymous)",
        "Brute-force credentials:   hydra -L users.txt -P pass.txt ftp://<target>",
        "Enumerate files:           nmap --script ftp-anon,ftp-ls <target>",
    ],
    "ssh": [
        "Check default/weak creds:  hydra -L users.txt -P pass.txt ssh://<target>",
        "Enumerate host keys:       ssh-keyscan <target>",
        "Banner grab:               nc <target> 22",
    ],
    "telnet": [
        "Connect & check banner:    telnet <target>",
        "Brute-force credentials:   hydra -l admin -P pass.txt telnet://<target>",
    ],
    "smtp": [
        "Enumerate users (VRFY):    smtp-user-enum -M VRFY -U users.txt -t <target>",
        "Test open relay:           swaks --to test@external.com --server <target>",
    ],
    "dns": [
        "Attempt zone transfer:     dig axfr @<target> <domain>",
        "Reverse lookup sweep:      dnsrecon -r <subnet>/24 -n <target>",
    ],
    "http": [
        "Directory brute-force:     gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
        "Technology fingerprint:    whatweb http://<target>",
        "Search known CVEs:         searchsploit apache  (adjust for detected version)",
        "Scan web app:              nikto -h http://<target>",
    ],
    "https": [
        "Check TLS/cert issues:     sslscan <target>:443",
        "Directory brute-force:     gobuster dir -u https://<target> -w /usr/share/wordlists/dirb/common.txt",
        "Scan web app:              nikto -h https://<target>",
    ],
    "smb": [
        "List shares (no creds):    smbclient -L //<target> -N",
        "Enumerate with enum4linux: enum4linux -a <target>",
        "Check EternalBlue:         nmap --script smb-vuln-ms17-010 <target>",
        "Null session check:        rpcclient -U '' -N <target>",
    ],
    "netbios-ssn": [
        "NetBIOS enumeration:       nbtscan <target>",
        "Enumerate shares:          smbclient -L //<target> -N",
    ],
    "mysql": [
        "Connect (root, no pass):   mysql -h <target> -u root",
        "Brute-force:               hydra -l root -P pass.txt mysql://<target>",
        "Nmap scripts:              nmap --script mysql-info,mysql-databases <target>",
    ],
    "postgresql": [
        "Connect (postgres user):   psql -h <target> -U postgres",
        "Brute-force:               hydra -l postgres -P pass.txt postgres://<target>",
    ],
    "rdp": [
        "Check BlueKeep:            nmap --script rdp-vuln-ms12-020 <target>",
        "Brute-force:               crowbar -b rdp -s <target>/32 -u admin -C pass.txt",
    ],
    "vnc": [
        "Check no-auth:             nmap --script vnc-info,vnc-brute <target>",
        "Connect:                   vncviewer <target>",
    ],
    "redis": [
        "Connect (no auth):         redis-cli -h <target>",
        "Dump config:               redis-cli -h <target> CONFIG GET *",
    ],
    "mongodb": [
        "Connect (no auth):         mongo --host <target>",
        "Enumerate databases:       mongo --host <target> --eval 'show dbs'",
    ],
    "nfs": [
        "Show exports:              showmount -e <target>",
        "Mount share:               mount -t nfs <target>:/ /mnt/nfs",
    ],
    "oracle": [
        "SID enumeration:           nmap --script oracle-sid-brute <target>",
        "TNS version:               tnscmd10g version -h <target>",
    ],
}

# ── Outdated / EOL version patterns ──────────────────────────────────────────
# (service_keyword, version_substring) → advisory message
OUTDATED_VERSIONS: list[tuple[str, str, str]] = [
    ("openssh",  "6.",  "OpenSSH 6.x — consider checking for username enumeration (CVE-2018-15473)"),
    ("openssh",  "7.2", "OpenSSH 7.2 — vulnerable to user enumeration (CVE-2016-6210)"),
    ("openssh",  "7.4", "OpenSSH 7.4 — username enumeration (CVE-2018-15473) possible"),
    ("apache",   "2.2", "Apache 2.2 — End-of-Life; many unpatched CVEs"),
    ("apache",   "2.4.29", "Apache 2.4.29 — check CVE-2017-7679 / CVE-2017-9798"),
    ("nginx",    "1.14","Nginx 1.14 — check for HTTP/2 vulnerabilities"),
    ("vsftpd",   "2.3.4","vsftpd 2.3.4 — backdoor vulnerability (CVE-2011-2523)!"),
    ("proftpd",  "1.3.3","ProFTPD 1.3.3c — remote code execution (CVE-2010-4221)"),
    ("samba",    "3.",  "Samba 3.x — multiple critical CVEs; check SambaCry (CVE-2017-7494)"),
    ("samba",    "4.0", "Samba 4.0.x — check CVE-2015-0240"),
    ("iis",      "6.0", "IIS 6.0 — EOL; WebDAV buffer overflow (CVE-2017-7269)"),
    ("iis",      "7.0", "IIS 7.0 — EOL; multiple unpatched CVEs"),
    ("mysql",    "5.0", "MySQL 5.0 — EOL; many unpatched CVEs"),
    ("mysql",    "5.5", "MySQL 5.5 — EOL; privilege escalation risks"),
    ("php",      "5.",  "PHP 5.x — EOL; numerous RCE and injection vulnerabilities"),
    ("php",      "7.0", "PHP 7.0 — EOL; check for deserialization and injection bugs"),
    ("ssl",      "sslv2","SSLv2 detected — DROWN attack risk (CVE-2016-0800)"),
    ("ssl",      "sslv3","SSLv3 detected — POODLE attack risk (CVE-2014-3566)"),
]
