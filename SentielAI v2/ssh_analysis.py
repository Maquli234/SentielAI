"""
SentinelAI SSH Analysis Module
================================
Analyses Nmap SSH script output for:
  • Outdated versions
  • Weak key-exchange and cipher algorithms
  • Password authentication enabled
  • User enumeration vulnerability
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from parser import HostResult, PortInfo

logger = logging.getLogger("sentinelai.ssh_analysis")

# Weak algorithms to flag
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
}

WEAK_CIPHERS = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour",
    "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc",
}

WEAK_MAC = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com",
}


@dataclass
class SSHAnalysis:
    target:            str
    port:              int
    banner:            str = ""
    version:           str = ""
    weak_kex:          list[str] = field(default_factory=list)
    weak_ciphers:      list[str] = field(default_factory=list)
    weak_macs:         list[str] = field(default_factory=list)
    password_auth:     Optional[bool] = None
    vuln_user_enum:    Optional[bool] = None
    findings:          list[str] = field(default_factory=list)
    suggestions:       list[str] = field(default_factory=list)


def analyze_ssh(host: HostResult) -> Optional[SSHAnalysis]:
    """Analyse SSH ports on a host and return findings."""
    ssh_ports = [p for p in host.open_ports if p.port == 22 or "ssh" in p.service.lower()]
    if not ssh_ports:
        return None

    port = ssh_ports[0]
    analysis = SSHAnalysis(target=host.address, port=port.port, version=port.version_string)

    for script in port.scripts:
        sid = script.script_id
        out = script.output

        # Algorithm enumeration
        if sid == "ssh2-enum-algos":
            _parse_algos(out, analysis)

        # Banner / auth methods
        if sid in ("ssh-auth-methods", "ssh-hostkey"):
            if "password" in out.lower():
                analysis.password_auth = True
                analysis.findings.append("Password authentication enabled")
                analysis.suggestions.append(
                    f"Brute-force SSH:  hydra -L users.txt -P pass.txt ssh://{host.address}"
                )

        # Brute force results
        if sid == "ssh-brute":
            if "valid credentials" in out.lower():
                analysis.findings.append(f"SSH credentials found: {out[:200]}")

    # Version-based checks
    v = (port.product + " " + port.version).lower()
    if "7.2" in v or "7.4" in v:
        analysis.vuln_user_enum = True
        analysis.findings.append("Possible username enumeration (CVE-2018-15473)")
        analysis.suggestions.append(
            f"User enum:  msf auxiliary/scanner/ssh/ssh_enumusers  target={host.address}"
        )

    analysis.suggestions += [
        f"SSH audit:      ssh-audit {host.address}",
        f"Banner grab:   ssh-keyscan {host.address}",
        f"Nmap algos:    nmap --script ssh2-enum-algos -p {port.port} {host.address}",
    ]

    return analysis


def _parse_algos(output: str, analysis: SSHAnalysis) -> None:
    lines = output.lower().splitlines()
    section = ""
    for line in lines:
        line = line.strip()
        if "kex" in line:
            section = "kex"
        elif "encrypt" in line or "cipher" in line:
            section = "cipher"
        elif "mac" in line:
            section = "mac"
        else:
            if section == "kex" and any(w in line for w in WEAK_KEX):
                match = next((w for w in WEAK_KEX if w in line), line)
                analysis.weak_kex.append(match)
                analysis.findings.append(f"Weak KEX algorithm: {match}")
            elif section == "cipher" and any(w in line for w in WEAK_CIPHERS):
                match = next((w for w in WEAK_CIPHERS if w in line), line)
                analysis.weak_ciphers.append(match)
                analysis.findings.append(f"Weak cipher: {match}")
            elif section == "mac" and any(w in line for w in WEAK_MAC):
                match = next((w for w in WEAK_MAC if w in line), line)
                analysis.weak_macs.append(match)
                analysis.findings.append(f"Weak MAC: {match}")
