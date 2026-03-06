"""
SentinelAI SMB Enumeration Module
====================================
Generates SMB enumeration commands and analyses Nmap SMB script output.
Does NOT directly execute smbclient / enum4linux — just surfaces the commands.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from parser import HostResult

logger = logging.getLogger("sentinelai.smb_enum")


@dataclass
class SMBFindings:
    target:          str
    signing_required: Optional[bool] = None
    os_info:         str = ""
    domain:          str = ""
    share_names:     list[str] = field(default_factory=list)
    vuln_ms17_010:   Optional[bool] = None
    null_session:    Optional[bool] = None
    findings:        list[str] = field(default_factory=list)
    suggestions:     list[str] = field(default_factory=list)


def analyze_smb_scripts(host: HostResult) -> SMBFindings:
    """
    Parse NSE SMB script output from a HostResult and produce SMBFindings.
    """
    target = host.address
    sf = SMBFindings(target=target)

    all_scripts = list(host.host_scripts)
    for port in host.open_ports:
        if port.port in (139, 445):
            all_scripts.extend(port.scripts)

    for script in all_scripts:
        sid = script.script_id
        out = script.output
        out_lower = out.lower()

        # SMB signing
        if "smb2-security-mode" in sid:
            sf.signing_required = "signing enabled and required" in out_lower
            if not sf.signing_required:
                sf.findings.append("SMB signing NOT required — NTLM relay possible")
                sf.suggestions.append(
                    f"NTLM relay:  responder -I eth0 &  ntlmrelayx.py -t smb://{target}"
                )

        # OS discovery
        if "smb-os-discovery" in sid:
            sf.os_info = out.strip()
            for line in out.splitlines():
                if "domain:" in line.lower():
                    sf.domain = line.split(":", 1)[-1].strip()

        # Share enumeration
        if "smb-enum-shares" in sid:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("\\\\") or "IPC$" in line or "ADMIN$" in line:
                    sf.share_names.append(line)

        # EternalBlue
        if "smb-vuln-ms17-010" in sid:
            sf.vuln_ms17_010 = "VULNERABLE" in out
            if sf.vuln_ms17_010:
                sf.findings.append("VULNERABLE to EternalBlue (MS17-010)!")
                sf.suggestions.append(
                    f"Check MSF:   use exploit/windows/smb/ms17_010_eternalblue  →  set RHOSTS {target}"
                )

    # Always suggest these
    sf.suggestions += [
        f"Null session:       smbclient -L //{target} -N",
        f"Full enum:          enum4linux -a {target}",
        f"CrackMapExec:       crackmapexec smb {target}",
        f"Nmap SMB scripts:   nmap --script smb-vuln-ms17-010,smb-enum-shares,smb-os-discovery {target}",
    ]

    return sf
