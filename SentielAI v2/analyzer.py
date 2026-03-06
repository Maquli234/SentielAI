"""
SentinelAI Analyzer Module
===========================
Produces structured findings from a parsed ScanResult:
• RiskyPort, OutdatedService, Finding, RiskScore
• Attack surface scoring
No network activity — pure analysis.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from config import RISKY_PORTS, OUTDATED_VERSIONS, SERVICE_KB, RISK_WEIGHTS
from parser import ScanResult, HostResult, PortInfo, ScriptResult

logger = logging.getLogger("sentinelai.analyzer")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class RiskyPort:
    port:     int
    service:  str
    risk:     str
    category: str
    note:     str = ""


@dataclass
class OutdatedService:
    port:     int
    service:  str
    version:  str
    severity: str
    advisory: str


@dataclass
class Finding:
    severity: str
    title:    str
    detail:   str
    port:     Optional[int] = None


@dataclass
class RiskScore:
    score:   float          # 0.0 – 10.0
    factors: list[str]      = field(default_factory=list)
    label:   str = ""       # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"

    def __post_init__(self):
        if not self.label:
            if   self.score >= 8:  self.label = "CRITICAL"
            elif self.score >= 6:  self.label = "HIGH"
            elif self.score >= 4:  self.label = "MEDIUM"
            elif self.score >= 2:  self.label = "LOW"
            else:                  self.label = "INFORMATIONAL"


@dataclass
class HostAnalysis:
    host:              HostResult
    risky_ports:       list[RiskyPort]      = field(default_factory=list)
    outdated:          list[OutdatedService]= field(default_factory=list)
    findings:          list[Finding]        = field(default_factory=list)
    suggestions:       list[str]            = field(default_factory=list)
    attack_vectors:    list[str]            = field(default_factory=list)
    risk_score:        Optional[RiskScore]  = None


@dataclass
class AnalysisReport:
    scan_command:   str
    scan_time:      str
    host_analyses:  list[HostAnalysis] = field(default_factory=list)

    @property
    def highest_risk(self) -> Optional[HostAnalysis]:
        return max(
            self.host_analyses,
            key=lambda ha: ha.risk_score.score if ha.risk_score else 0,
            default=None,
        )


# ─────────────────────────────────────────────────────────────────────────────

def analyze(scan: ScanResult) -> AnalysisReport:
    report = AnalysisReport(scan_command=scan.command, scan_time=scan.start_time)
    for host in scan.hosts:
        ha = _analyze_host(host)
        report.host_analyses.append(ha)
    report.host_analyses.sort(
        key=lambda h: h.risk_score.score if h.risk_score else 0, reverse=True
    )
    return report


def _analyze_host(host: HostResult) -> HostAnalysis:
    ha = HostAnalysis(host=host)

    for port in host.open_ports:
        _flag_risky_port(port, ha)
        _flag_outdated(port, ha)
        _analyze_scripts(port, ha)
        _collect_suggestions(port, ha)
        _collect_vectors(port, ha)

    _analyze_os(host, ha)
    _analyze_host_scripts(host, ha)
    ha.risk_score = _compute_risk(ha)

    # Deduplicate
    ha.suggestions   = list(dict.fromkeys(ha.suggestions))
    ha.attack_vectors = list(dict.fromkeys(ha.attack_vectors))

    # Sort findings by severity
    ha.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)

    logger.debug(
        "Host %s → risk %.1f (%s), %d ports, %d findings",
        host.address, ha.risk_score.score, ha.risk_score.label,
        len(host.open_ports), len(ha.findings),
    )
    return ha


def _flag_risky_port(port: PortInfo, ha: HostAnalysis) -> None:
    if port.port in RISKY_PORTS:
        data = RISKY_PORTS[port.port]
        ha.risky_ports.append(RiskyPort(
            port=port.port,
            service=data["service"],
            risk=data["risk"],
            category=data["category"],
        ))


def _flag_outdated(port: PortInfo, ha: HostAnalysis) -> None:
    combined = f"{port.service} {port.product} {port.version} {port.extra_info}".lower()
    for svc_kw, ver_kw, severity, advisory in OUTDATED_VERSIONS:
        if svc_kw in combined and ver_kw.lower() in combined:
            ha.outdated.append(OutdatedService(
                port=port.port,
                service=port.display_service,
                version=port.version_string,
                severity=severity,
                advisory=advisory,
            ))
            ha.findings.append(Finding(
                severity=severity,
                title=f"Potentially vulnerable version on port {port.port}",
                detail=advisory,
                port=port.port,
            ))


def _analyze_scripts(port: PortInfo, ha: HostAnalysis) -> None:
    target = ha.host.address
    for script in port.scripts:
        out = script.output.lower()
        sid = script.script_id

        # Anonymous FTP
        if sid == "ftp-anon" and "anonymous ftp login allowed" in out:
            ha.findings.append(Finding(
                severity="HIGH",
                title=f"Anonymous FTP login allowed (port {port.port})",
                detail=script.output[:300],
                port=port.port,
            ))
            ha.suggestions.append(f"Connect via anonymous FTP:  ftp {target}  (user: anonymous)")

        # SMB signing
        if "smb2-security-mode" in sid and "signing enabled and not required" in out:
            ha.findings.append(Finding(
                severity="MEDIUM",
                title="SMB signing not required — relay attack possible",
                detail="Use Responder + ntlmrelayx for NTLM relay attacks.",
                port=port.port,
            ))

        # Vuln scripts
        if "VULNERABLE" in script.output:
            ha.findings.append(Finding(
                severity="CRITICAL",
                title=f"Vulnerability detected by NSE script '{sid}' on port {port.port}",
                detail=script.output[:500],
                port=port.port,
            ))

        # HTTP title (informational)
        if sid == "http-title":
            ha.findings.append(Finding(
                severity="INFO",
                title=f"HTTP title on port {port.port}: {script.output[:80]}",
                detail=script.output[:200],
                port=port.port,
            ))

        # SSL cert info
        if sid == "ssl-cert":
            ha.findings.append(Finding(
                severity="INFO",
                title=f"TLS certificate details on port {port.port}",
                detail=script.output[:300],
                port=port.port,
            ))


def _collect_suggestions(port: PortInfo, ha: HostAnalysis) -> None:
    target = ha.host.address
    svc    = (port.service or port.product or "").lower()

    # Service KB lookup
    for key, data in SERVICE_KB.items():
        if key in svc:
            for s in data["suggestions"]:
                ha.suggestions.append(s.replace("<target>", target))
            break  # first match only

    # Searchsploit hint for any version
    if port.version_string:
        ha.suggestions.append(
            f"Search exploits:            searchsploit {port.version_string[:40]}"
        )


def _collect_vectors(port: PortInfo, ha: HostAnalysis) -> None:
    svc = (port.service or port.product or "").lower()
    for key, data in SERVICE_KB.items():
        if key in svc:
            ha.attack_vectors.extend(data.get("attack_vectors", []))
            break


def _analyze_os(host: HostResult, ha: HostAnalysis) -> None:
    if not host.os_guesses:
        return
    best = host.os_guesses[0]
    if best.accuracy >= 80:
        ha.findings.append(Finding(
            severity="INFO",
            title=f"OS detected: {best.name}  ({best.accuracy}%)",
            detail=f"Family: {best.os_family}  Gen: {best.os_gen}  Type: {best.os_type}",
        ))
    name_l = best.name.lower()
    if "windows xp" in name_l or "server 2003" in name_l:
        ha.findings.append(Finding(
            severity="CRITICAL",
            title="End-of-Life Windows OS detected",
            detail=f"{best.name} — likely vulnerable to MS08-067, MS17-010 and many others.",
        ))


def _analyze_host_scripts(host: HostResult, ha: HostAnalysis) -> None:
    for script in host.host_scripts:
        if "VULNERABLE" in script.output:
            ha.findings.append(Finding(
                severity="CRITICAL",
                title=f"Host-level vulnerability from script '{script.script_id}'",
                detail=script.output[:500],
            ))


def _compute_risk(ha: HostAnalysis) -> RiskScore:
    score   = 0.0
    factors = []

    for rp in ha.risky_ports:
        w = {"CRITICAL": RISK_WEIGHTS["critical_port"],
             "HIGH":     RISK_WEIGHTS["high_port"],
             "MEDIUM":   RISK_WEIGHTS["medium_port"]}.get(rp.risk, 0.5)
        score += w
        factors.append(f"{rp.risk} risk port {rp.port} ({rp.service})")

    for od in ha.outdated:
        w = RISK_WEIGHTS["outdated_version"]
        if od.severity == "CRITICAL":
            w *= 1.4
        score += w
        factors.append(f"Outdated {od.service} {od.version}")

    for f in ha.findings:
        if f.severity == "CRITICAL":
            score += RISK_WEIGHTS["vuln_script_hit"]
            factors.append(f.title[:60])
        elif f.severity == "HIGH":
            score += RISK_WEIGHTS["anon_service"]

    # Normalise to 0–10
    score = min(round(score, 1), 10.0)
    return RiskScore(score=score, factors=factors[:8])  # top-8 factors


# ── Scan graph (ASCII fallback + networkx if available) ───────────────────────

def build_graph(report: AnalysisReport) -> str:
    """Return an ASCII tree of target → ports."""
    lines = []
    for ha in report.host_analyses:
        host = ha.host
        lines.append(f"  {host.display_name}  [{ha.risk_score.label if ha.risk_score else '?'}]")
        ports = host.open_ports
        for i, p in enumerate(ports):
            connector = "└─" if i == len(ports) - 1 else "├─"
            lines.append(f"    {connector} {p.port}/{p.protocol}  {p.full_label}")
    return "\n".join(lines) if lines else "  (no hosts)"
