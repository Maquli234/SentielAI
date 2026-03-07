"""
SentinelAI Extension — Tool Orchestrator
=========================================
Runs external pentest tools based on detected services from a HostAnalysis.
Produces parsed ToolResult objects.  DOES NOT modify scanner.py.

Usage:
    from tool_orchestrator import ToolOrchestrator
    orch    = ToolOrchestrator()
    results = orch.auto_run(host_analysis)
"""
from __future__ import annotations
import re, shutil, subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analyzer import HostAnalysis


@dataclass
class ToolResult:
    tool:       str
    target:     str
    command:    str
    returncode: int
    stdout:     str
    stderr:     str
    parsed:     dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def short_summary(self) -> str:
        if not self.success and self.returncode == -1:
            return self.stderr or "Tool not available"
        n = len(self.parsed)
        return f"{n} result field(s)" if n else "No parsed output"


def _avail(tool: str) -> bool:
    return shutil.which(tool) is not None

def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"

def _is_domain(s: str) -> bool:
    return not re.match(r"^[\d\.]+$", s)


class ToolOrchestrator:
    """
    Automatically selects and runs tools based on services in a HostAnalysis.
    All tool availability is checked before execution — graceful skip if missing.
    """

    def auto_run(self, ha: "HostAnalysis") -> list[ToolResult]:
        target  = ha.host.address or ha.host.hostname
        services = {(p.service + " " + p.product).lower() for p in ha.host.open_ports}
        ports    = {p.port for p in ha.host.open_ports}
        results: list[ToolResult] = []

        # Web services
        is_web = any(s in " ".join(services) for s in ["http","https","www","apache","nginx","iis"])
        if is_web:
            for port in [p for p in ha.host.open_ports if p.port in (80,8080,8000,443,8443)]:
                scheme = "https" if port.port in (443,8443) or port.tunnel == "ssl" else "http"
                url    = f"{scheme}://{target}:{port.port}"
                if _avail("gobuster"): results.append(self.gobuster(url, target))
                if _avail("whatweb"):  results.append(self.whatweb(url, target))
                if _avail("nikto"):    results.append(self.nikto(url, target))
                if _avail("ffuf"):     results.append(self.ffuf(url, target))

        # SMB
        if any(s in " ".join(services) for s in ["smb","netbios","microsoft-ds","samba"]):
            if _avail("enum4linux"): results.append(self.enum4linux(target))

        # Subdomain / DNS recon
        if _is_domain(target):
            if   _avail("subfinder"): results.append(self.subfinder(target))
            elif _avail("amass"):     results.append(self.amass(target))

        return results

    # ── Individual tool wrappers ──────────────────────────────────────
    def gobuster(self, url: str, target: str,
                 wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> ToolResult:
        cmd = ["gobuster","dir","-u",url,"-w",wordlist,"-q","--no-progress"]
        rc, out, err = _run(cmd)
        paths = re.findall(r"(/[\w./\-]+)\s+\(Status:\s*(\d+)", out)
        return ToolResult("gobuster", target, " ".join(cmd), rc, out, err,
                          {"paths": [{"path":p,"status":int(s)} for p,s in paths]})

    def whatweb(self, url: str, target: str) -> ToolResult:
        cmd = ["whatweb","--color=never", url]
        rc, out, err = _run(cmd, timeout=30)
        return ToolResult("whatweb", target, " ".join(cmd), rc, out, err,
                          {"technologies": out.strip()})

    def nikto(self, url: str, target: str) -> ToolResult:
        cmd = ["nikto","-h",url,"-nointeractive"]
        rc, out, err = _run(cmd, timeout=180)
        findings = [l.lstrip("+ ") for l in out.splitlines()
                    if l.startswith("+ ") and "OSVDB" not in l]
        return ToolResult("nikto", target, " ".join(cmd), rc, out, err,
                          {"findings": findings})

    def ffuf(self, url: str, target: str,
             wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> ToolResult:
        cmd = ["ffuf","-u",f"{url}/FUZZ","-w",wordlist,"-s"]
        rc, out, err = _run(cmd, timeout=120)
        return ToolResult("ffuf", target, " ".join(cmd), rc, out, err,
                          {"results": [l for l in out.splitlines() if l.strip()]})

    def enum4linux(self, target: str) -> ToolResult:
        cmd = ["enum4linux","-a",target]
        rc, out, err = _run(cmd, timeout=120)
        users  = re.findall(r"user:\[([^\]]+)\]",   out, re.IGNORECASE)
        shares = re.findall(r"Sharename\s+(\S+)", out)
        return ToolResult("enum4linux", target, " ".join(cmd), rc, out, err,
                          {"users": users, "shares": shares})

    def subfinder(self, domain: str) -> ToolResult:
        cmd = ["subfinder","-d",domain,"-silent"]
        rc, out, err = _run(cmd, timeout=120)
        return ToolResult("subfinder", domain, " ".join(cmd), rc, out, err,
                          {"subdomains": [l.strip() for l in out.splitlines() if l.strip()]})

    def amass(self, domain: str) -> ToolResult:
        cmd = ["amass","enum","-passive","-d",domain]
        rc, out, err = _run(cmd, timeout=180)
        return ToolResult("amass", domain, " ".join(cmd), rc, out, err,
                          {"subdomains": [l.strip() for l in out.splitlines() if l.strip()]})
