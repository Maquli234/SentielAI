"""
SentinelAI Configuration
=========================
Central configuration, scan profiles, risk data, and service knowledge base.
FOR AUTHORIZED PENETRATION TESTING / EDUCATIONAL LAB USE ONLY.
"""

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
SCANS_DIR     = BASE_DIR / "scans"
LOGS_DIR      = BASE_DIR / "logs"
DB_PATH       = BASE_DIR / "database" / "targets.db"
REPORTS_DIR   = BASE_DIR / "reports"

for d in (SCANS_DIR, LOGS_DIR, DB_PATH.parent, REPORTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ── Tool identity ─────────────────────────────────────────────────────────────
TOOL_NAME    = "SentinelAI"
TOOL_VERSION = "2.0.0"
DISCLAIMER   = (
    "FOR AUTHORIZED PENETRATION TESTING / EDUCATIONAL LAB ENVIRONMENTS ONLY.\n"
    "Never scan or test systems without explicit written permission."
)

# ── LLM Settings ─────────────────────────────────────────────────────────────
LLM_MODEL      = "claude-sonnet-4-20250514"
LLM_MAX_TOKENS = 1500

# ── Nmap scan profiles ────────────────────────────────────────────────────────
SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "label": "Quick Scan",
        "description": "Fast top-100 port recon",
        "args": ["-T4", "-F"],
    },
    "full": {
        "label": "Full Scan",
        "description": "All ports + service/version detection",
        "args": ["-sS", "-sV", "-p-"],
    },
    "os": {
        "label": "OS Detection",
        "description": "TCP/IP OS fingerprinting",
        "args": ["-O"],
    },
    "vuln": {
        "label": "Vulnerability Scan",
        "description": "NSE vulnerability scripts",
        "args": ["--script", "vuln"],
    },
    "stealth": {
        "label": "Stealth Scan",
        "description": "SYN scan, skip ping",
        "args": ["-sS", "-Pn"],
    },
    "ports": {
        "label": "Service Scan",
        "description": "Version + default NSE scripts",
        "args": ["-sV", "--script", "default"],
    },
    "web": {
        "label": "Web Scan",
        "description": "HTTP/HTTPS focused NSE scripts",
        "args": [
            "-p", "80,443,8080,8443,8000,8888",
            "--script",
            "http-title,http-headers,http-methods,http-server-header,"
            "http-auth-finder,http-robots.txt,ssl-cert,ssl-enum-ciphers",
        ],
    },
    "smb": {
        "label": "SMB Scan",
        "description": "SMB enumeration scripts",
        "args": [
            "-p", "139,445",
            "--script",
            "smb-vuln-ms17-010,smb2-security-mode,smb-os-discovery,"
            "smb-enum-shares,smb-enum-users",
        ],
    },
}

VALID_SPEEDS = {"T0", "T1", "T2", "T3", "T4", "T5"}

# ── Risk scoring weights ──────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "critical_port":       3.0,
    "high_port":           2.0,
    "medium_port":         1.0,
    "outdated_version":    2.5,
    "vuln_script_hit":     3.5,
    "anon_service":        2.0,
    "weak_algorithm":      1.5,
    "missing_header":      0.5,
    "open_db":             3.0,
}

# ── Risky ports ───────────────────────────────────────────────────────────────
RISKY_PORTS: dict[int, dict] = {
    21:    {"service": "FTP",        "risk": "HIGH",     "category": "cleartext"},
    22:    {"service": "SSH",        "risk": "MEDIUM",   "category": "remote_access"},
    23:    {"service": "Telnet",     "risk": "CRITICAL", "category": "cleartext"},
    25:    {"service": "SMTP",       "risk": "MEDIUM",   "category": "mail"},
    53:    {"service": "DNS",        "risk": "MEDIUM",   "category": "infrastructure"},
    69:    {"service": "TFTP",       "risk": "HIGH",     "category": "cleartext"},
    80:    {"service": "HTTP",       "risk": "MEDIUM",   "category": "web"},
    110:   {"service": "POP3",       "risk": "MEDIUM",   "category": "mail"},
    111:   {"service": "RPCBind",    "risk": "HIGH",     "category": "rpc"},
    135:   {"service": "MSRPC",      "risk": "HIGH",     "category": "windows"},
    137:   {"service": "NetBIOS-NS", "risk": "HIGH",     "category": "windows"},
    139:   {"service": "NetBIOS",    "risk": "HIGH",     "category": "windows"},
    143:   {"service": "IMAP",       "risk": "MEDIUM",   "category": "mail"},
    161:   {"service": "SNMP",       "risk": "HIGH",     "category": "management"},
    389:   {"service": "LDAP",       "risk": "HIGH",     "category": "directory"},
    443:   {"service": "HTTPS",      "risk": "MEDIUM",   "category": "web"},
    445:   {"service": "SMB",        "risk": "CRITICAL", "category": "windows"},
    512:   {"service": "rexec",      "risk": "CRITICAL", "category": "legacy"},
    513:   {"service": "rlogin",     "risk": "CRITICAL", "category": "legacy"},
    514:   {"service": "rsh",        "risk": "CRITICAL", "category": "legacy"},
    1433:  {"service": "MSSQL",      "risk": "HIGH",     "category": "database"},
    1521:  {"service": "Oracle",     "risk": "HIGH",     "category": "database"},
    2049:  {"service": "NFS",        "risk": "HIGH",     "category": "file_sharing"},
    2375:  {"service": "Docker",     "risk": "CRITICAL", "category": "container"},
    2376:  {"service": "Docker TLS", "risk": "HIGH",     "category": "container"},
    3306:  {"service": "MySQL",      "risk": "HIGH",     "category": "database"},
    3389:  {"service": "RDP",        "risk": "HIGH",     "category": "remote_access"},
    4369:  {"service": "Erlang EPM", "risk": "HIGH",     "category": "messaging"},
    5432:  {"service": "PostgreSQL", "risk": "HIGH",     "category": "database"},
    5672:  {"service": "RabbitMQ",   "risk": "HIGH",     "category": "messaging"},
    5900:  {"service": "VNC",        "risk": "CRITICAL", "category": "remote_access"},
    6379:  {"service": "Redis",      "risk": "CRITICAL", "category": "database"},
    8080:  {"service": "HTTP-alt",   "risk": "MEDIUM",   "category": "web"},
    8443:  {"service": "HTTPS-alt",  "risk": "MEDIUM",   "category": "web"},
    9200:  {"service": "Elasticsearch","risk": "CRITICAL","category": "database"},
    9300:  {"service": "ES Transport","risk": "HIGH",    "category": "database"},
    11211: {"service": "Memcached",  "risk": "HIGH",     "category": "database"},
    27017: {"service": "MongoDB",    "risk": "CRITICAL", "category": "database"},
    27018: {"service": "MongoDB",    "risk": "HIGH",     "category": "database"},
}

# ── Service knowledge base ────────────────────────────────────────────────────
SERVICE_KB: dict[str, dict] = {
    "ftp": {
        "description": "File Transfer Protocol — clear-text credential transmission",
        "attack_vectors": ["anonymous login", "brute force", "credential sniffing"],
        "tools": ["hydra", "medusa", "ftp-anon NSE", "nmap"],
        "suggestions": [
            "Test anonymous login:       ftp <target>  [user: anonymous]",
            "NSE anonymous check:        nmap --script ftp-anon <target>",
            "Brute-force credentials:    hydra -L users.txt -P pass.txt ftp://<target>",
            "List directory:             nmap --script ftp-ls <target>",
        ],
    },
    "ssh": {
        "description": "Secure Shell — remote access",
        "attack_vectors": ["weak credentials", "outdated algorithms", "user enumeration"],
        "tools": ["hydra", "ssh-audit", "nmap", "medusa"],
        "suggestions": [
            "Audit SSH config:           ssh-audit <target>",
            "Banner grab:               ssh-keyscan <target>",
            "Brute-force:               hydra -L users.txt -P pass.txt ssh://<target>",
            "Check algorithms:          nmap --script ssh2-enum-algos <target>",
        ],
    },
    "telnet": {
        "description": "Legacy clear-text remote access protocol",
        "attack_vectors": ["credential sniffing", "brute force", "clear-text session hijack"],
        "tools": ["hydra", "telnet", "wireshark"],
        "suggestions": [
            "Connect and grab banner:    telnet <target>",
            "Brute-force:               hydra -l admin -P pass.txt telnet://<target>",
        ],
    },
    "smtp": {
        "description": "Simple Mail Transfer Protocol",
        "attack_vectors": ["user enumeration (VRFY/EXPN)", "open relay", "brute force"],
        "tools": ["smtp-user-enum", "swaks", "nmap"],
        "suggestions": [
            "Enumerate users:           smtp-user-enum -M VRFY -U users.txt -t <target>",
            "Test open relay:           swaks --to test@external.com --server <target>",
            "NSE scripts:               nmap --script smtp-enum-users,smtp-open-relay <target>",
        ],
    },
    "dns": {
        "description": "Domain Name System",
        "attack_vectors": ["zone transfer", "subdomain enumeration", "cache poisoning"],
        "tools": ["dig", "dnsrecon", "fierce", "subfinder"],
        "suggestions": [
            "Zone transfer:             dig axfr @<target> <domain>",
            "Reverse sweep:             dnsrecon -r <subnet>/24 -n <target>",
            "NSE zone transfer:         nmap --script dns-zone-transfer <target>",
        ],
    },
    "http": {
        "description": "Hypertext Transfer Protocol — web server",
        "attack_vectors": ["directory traversal", "CVEs", "weak auth", "injection"],
        "tools": ["gobuster", "nikto", "whatweb", "ffuf", "burpsuite"],
        "suggestions": [
            "Fingerprint:               whatweb http://<target>",
            "Directory scan:            gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
            "Vulnerability scan:        nikto -h http://<target>",
            "Fuzzing:                   ffuf -u http://<target>/FUZZ -w wordlist.txt",
            "Search CVEs:               searchsploit <service_version>",
        ],
    },
    "https": {
        "description": "HTTP over TLS",
        "attack_vectors": ["weak TLS", "expired certs", "HTTP downgrade", "web app vulns"],
        "tools": ["sslscan", "testssl.sh", "gobuster", "nikto"],
        "suggestions": [
            "TLS audit:                 sslscan <target>:443",
            "Comprehensive TLS test:    testssl.sh <target>",
            "Directory scan:            gobuster dir -u https://<target> -w common.txt",
            "Scan web app:              nikto -h https://<target>",
        ],
    },
    "smb": {
        "description": "Server Message Block — Windows file sharing",
        "attack_vectors": ["null session", "EternalBlue", "share enumeration", "relay attacks"],
        "tools": ["smbclient", "enum4linux", "crackmapexec", "nmap"],
        "suggestions": [
            "List shares (null):        smbclient -L //<target> -N",
            "Full enumeration:          enum4linux -a <target>",
            "CrackMapExec:              crackmapexec smb <target>",
            "Check EternalBlue:         nmap --script smb-vuln-ms17-010 <target>",
            "Check signing:             nmap --script smb2-security-mode <target>",
        ],
    },
    "rdp": {
        "description": "Remote Desktop Protocol",
        "attack_vectors": ["BlueKeep", "brute force", "credential stuffing"],
        "tools": ["xfreerdp", "crowbar", "nmap"],
        "suggestions": [
            "Check BlueKeep:            nmap --script rdp-vuln-ms12-020 <target>",
            "Brute-force:               crowbar -b rdp -s <target>/32 -u admin -C pass.txt",
            "Connect:                   xfreerdp /v:<target> /u:admin",
        ],
    },
    "mysql": {
        "description": "MySQL database server",
        "attack_vectors": ["default credentials", "remote root", "SQL injection"],
        "tools": ["mysql", "hydra", "nmap", "sqlmap"],
        "suggestions": [
            "Connect (root no pass):    mysql -h <target> -u root",
            "Brute-force:               hydra -l root -P pass.txt mysql://<target>",
            "NSE info:                  nmap --script mysql-info,mysql-databases <target>",
        ],
    },
    "postgresql": {
        "description": "PostgreSQL database server",
        "attack_vectors": ["default credentials", "trust auth", "pgBouncer misconfig"],
        "tools": ["psql", "hydra", "nmap"],
        "suggestions": [
            "Connect:                   psql -h <target> -U postgres",
            "Brute-force:               hydra -l postgres -P pass.txt postgres://<target>",
            "NSE scripts:               nmap --script pgsql-brute <target>",
        ],
    },
    "mssql": {
        "description": "Microsoft SQL Server",
        "attack_vectors": ["default credentials", "xp_cmdshell", "linked servers"],
        "tools": ["impacket", "crackmapexec", "nmap"],
        "suggestions": [
            "NSE scan:                  nmap --script ms-sql-info,ms-sql-config <target>",
            "CrackMapExec:              crackmapexec mssql <target> -u sa -p pass.txt",
            "Connect:                   impacket-mssqlclient <target>",
        ],
    },
    "vnc": {
        "description": "Virtual Network Computing — remote desktop",
        "attack_vectors": ["no authentication", "weak password", "brute force"],
        "tools": ["vncviewer", "nmap", "hydra"],
        "suggestions": [
            "Check no-auth:             nmap --script vnc-info,vnc-brute <target>",
            "Connect:                   vncviewer <target>",
        ],
    },
    "redis": {
        "description": "Redis in-memory data store",
        "attack_vectors": ["unauthenticated access", "config write", "SSRF abuse"],
        "tools": ["redis-cli", "nmap"],
        "suggestions": [
            "Connect (no auth):         redis-cli -h <target>",
            "Config dump:               redis-cli -h <target> CONFIG GET *",
            "Check INFO:                redis-cli -h <target> INFO",
        ],
    },
    "mongodb": {
        "description": "MongoDB NoSQL database",
        "attack_vectors": ["unauthenticated access", "data exfiltration"],
        "tools": ["mongosh", "nmap"],
        "suggestions": [
            "Connect:                   mongosh --host <target>",
            "List databases:            mongosh --host <target> --eval 'show dbs'",
        ],
    },
    "elasticsearch": {
        "description": "Elasticsearch distributed search engine",
        "attack_vectors": ["unauthenticated REST API", "data exfiltration"],
        "tools": ["curl", "elasticdump"],
        "suggestions": [
            "Check cluster info:        curl http://<target>:9200/",
            "List indices:              curl http://<target>:9200/_cat/indices",
            "Check nodes:               curl http://<target>:9200/_nodes",
        ],
    },
    "nfs": {
        "description": "Network File System",
        "attack_vectors": ["no_root_squash", "world-readable exports", "mount without auth"],
        "tools": ["showmount", "mount", "nmap"],
        "suggestions": [
            "Show exports:              showmount -e <target>",
            "NSE scan:                  nmap --script nfs-showmount,nfs-ls <target>",
            "Mount share:               mount -t nfs <target>:/ /mnt/nfs",
        ],
    },
    "docker": {
        "description": "Docker daemon API — container management",
        "attack_vectors": ["unauthenticated API", "container escape", "host filesystem access"],
        "tools": ["curl", "docker"],
        "suggestions": [
            "Check API:                 curl http://<target>:2375/v1.40/info",
            "List containers:           docker -H tcp://<target>:2375 ps",
            "Check images:              docker -H tcp://<target>:2375 images",
        ],
    },
    "snmp": {
        "description": "Simple Network Management Protocol",
        "attack_vectors": ["default community strings", "information disclosure", "v1/v2c weak auth"],
        "tools": ["snmpwalk", "onesixtyone", "snmp-check"],
        "suggestions": [
            "Walk (public):             snmpwalk -v2c -c public <target>",
            "Brute community strings:   onesixtyone <target> /usr/share/doc/onesixtyone/dict.txt",
            "Check with snmp-check:     snmp-check <target>",
        ],
    },
    "ldap": {
        "description": "Lightweight Directory Access Protocol",
        "attack_vectors": ["anonymous bind", "user enumeration", "credential brute force"],
        "tools": ["ldapsearch", "nmap", "enum4linux"],
        "suggestions": [
            "Anonymous bind query:      ldapsearch -x -H ldap://<target> -b '' -s base",
            "Enumerate users:           ldapsearch -x -H ldap://<target> -b 'dc=domain,dc=com'",
            "NSE scripts:               nmap --script ldap-rootdse,ldap-brute <target>",
        ],
    },
}

# ── Outdated version patterns ─────────────────────────────────────────────────
OUTDATED_VERSIONS: list[tuple[str, str, str, str]] = [
    ("vsftpd",    "2.3.4",  "CRITICAL", "vsftpd 2.3.4 backdoor — CVE-2011-2523 (RCE via port 6200)"),
    ("proftpd",   "1.3.3",  "HIGH",     "ProFTPD 1.3.3c RCE — CVE-2010-4221"),
    ("openssh",   "7.2",    "MEDIUM",   "OpenSSH 7.2 username enumeration — CVE-2016-6210"),
    ("openssh",   "7.4",    "MEDIUM",   "OpenSSH 7.4 username enumeration — CVE-2018-15473"),
    ("openssh",   "6.",     "HIGH",     "OpenSSH 6.x — multiple CVEs, check CVE-2016-0777"),
    ("apache",    "2.2.",   "HIGH",     "Apache 2.2 — EOL, many unpatched CVEs"),
    ("apache",    "2.4.49", "CRITICAL", "Apache 2.4.49 path traversal/RCE — CVE-2021-41773"),
    ("apache",    "2.4.50", "CRITICAL", "Apache 2.4.50 path traversal — CVE-2021-42013"),
    ("apache",    "2.4.29", "HIGH",     "Apache 2.4.29 — check CVE-2017-7679, CVE-2017-9798"),
    ("nginx",     "1.14",   "MEDIUM",   "Nginx 1.14 — check HTTP/2 vulnerabilities"),
    ("iis",       "6.0",    "CRITICAL", "IIS 6.0 EOL — WebDAV buffer overflow CVE-2017-7269"),
    ("iis",       "7.0",    "HIGH",     "IIS 7.0 EOL — multiple unpatched CVEs"),
    ("iis",       "7.5",    "MEDIUM",   "IIS 7.5 — check CVE-2015-1635 (HTTP.sys)"),
    ("samba",     "3.",     "CRITICAL", "Samba 3.x — SambaCry CVE-2017-7494 (RCE)"),
    ("samba",     "4.0",    "HIGH",     "Samba 4.0.x — check CVE-2015-0240"),
    ("mysql",     "5.0",    "HIGH",     "MySQL 5.0 EOL — many unpatched CVEs"),
    ("mysql",     "5.5",    "HIGH",     "MySQL 5.5 EOL — privilege escalation risks"),
    ("php",       "5.",     "CRITICAL", "PHP 5.x EOL — numerous RCE and injection vulns"),
    ("php",       "7.0",    "HIGH",     "PHP 7.0 EOL — deserialization and injection bugs"),
    ("php",       "7.1",    "HIGH",     "PHP 7.1 EOL — check CVE-2019-11043 if nginx"),
    ("openssl",   "1.0.1",  "CRITICAL", "OpenSSL 1.0.1 — Heartbleed CVE-2014-0160"),
    ("openssl",   "1.0.2",  "HIGH",     "OpenSSL 1.0.2 EOL — many unpatched CVEs"),
    ("tomcat",    "7.",     "HIGH",     "Tomcat 7.x EOL — check CVE-2017-12617 (JSP upload)"),
    ("tomcat",    "8.0",    "HIGH",     "Tomcat 8.0.x EOL — multiple CVEs"),
    ("tomcat",    "9.0.0",  "MEDIUM",   "Tomcat 9.0.0.M — early release, check CVEs"),
    ("jboss",     "4.",     "CRITICAL", "JBoss 4.x — unauthenticated RCE via JMX console"),
    ("struts",    "2.",     "CRITICAL", "Apache Struts 2 — check CVE-2017-5638 (Equifax breach)"),
    ("weblogic",  "10.",    "HIGH",     "WebLogic 10.x — check CVE-2019-2725 (deserialization)"),
    ("jenkins",   "1.",     "HIGH",     "Jenkins 1.x — check CVE-2016-0792, script console"),
]
