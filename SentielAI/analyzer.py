"""
SentinelAI Analyzer Module
===========================
Takes a parsed ScanResult and produces structured findings:

• RiskyPort   – known-dangerous port with contextual note
• OutdatedService – detected version that matches a known-vulnerable pattern
• Finding     – general flag (interesting configuration, enumeration opportunity)

All output is purely advisory — no exploitation is attempted.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from config import RISKY_PORTS, OUTDATED_VERSIONS, SERVICE_SUGGESTIONS
from parser import ScanResult, HostResult, PortInfo

logger = logging.getLogger("sentinelai.analyzer")


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RiskyPort:
    port:    int
    service: str
    risk:    str           # "HIGH", "MEDIUM", "LOW"
    note:    str


@dataclass
class OutdatedService:
    port:    int
    service: str
    version: str
    advisory: str


@dataclass
class Finding:
    severity: str          # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    title:    str
    detail:   str


@dataclass
class HostAnalysis:
    host:               HostResult
    risky_ports:        list[RiskyPort]       = field(default_factory=list)
    outdated_services:  list[OutdatedService] = field(default_factory=list)
    findings:           list[Finding]         = field(default_factory=list)
    suggestions:        list[str]             = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """
        Simple numeric risk score for sorting / highlighting.
        HIGH = 3, MEDIUM = 2, LOW / INFO = 1
        """
        score = 0
        weights = {"HIGH": 3, "CRITICAL": 4, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        for rp in self.risky_ports:
            score += weights.get(rp.risk, 1)
        for f in self.findings:
            score += weights.get(f.severity, 0)
        return score


@dataclass
class AnalysisReport:
    scan_command: str
    scan_time:    str
    host_analyses: list[HostAnalysis] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Main analyser entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze(scan_result: ScanResult) -> AnalysisReport:
    """
    Analyse every host in *scan_result* and return an AnalysisReport.
    """
    report = AnalysisReport(
        scan_command=scan_result.command,
        scan_time=scan_result.start_time,
    )

    for host in scan_result.hosts:
        ha = _analyze_host(host)
        report.host_analyses.append(ha)

    # Sort hosts: highest risk first
    report.host_analyses.sort(key=lambda h: h.risk_score, reverse=True)
    return report


# ─────────────────────────────────────────────────────────────────────────────
# Per-host analysis helpers
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_host(host: HostResult) -> HostAnalysis:
    ha = HostAnalysis(host=host)

    for port in host.open_ports:
        _check_risky_port(port, ha)
        _check_outdated_version(port, ha)
        _check_script_output(port, ha)
        _collect_suggestions(port, ha)

    _check_os_findings(host, ha)
    _check_host_scripts(host, ha)

    # Deduplicate suggestions
    seen: set[str] = set()
    unique: list[str] = []
    for s in ha.suggestions:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    ha.suggestions = unique

    logger.debug(
        "Host %s: %d risky ports, %d outdated, %d findings, %d suggestions",
        host.address,
        len(ha.risky_ports),
        len(ha.outdated_services),
        len(ha.findings),
        len(ha.suggestions),
    )
    return ha


def _check_risky_port(port: PortInfo, ha: HostAnalysis) -> None:
    """Flag ports that appear in RISKY_PORTS."""
    if port.port in RISKY_PORTS:
        rp_data = RISKY_PORTS[port.port]
        ha.risky_ports.append(
            RiskyPort(
                port=port.port,
                service=rp_data["service"],
                risk=rp_data["risk"],
                note=rp_data["note"],
            )
        )


def _check_outdated_version(port: PortInfo, ha: HostAnalysis) -> None:
    """Match service+version string against known vulnerable version patterns."""
    combined = (
        f"{port.service} {port.product} {port.version} {port.extra_info}"
    ).lower()

    for service_kw, version_kw, advisory in OUTDATED_VERSIONS:
        if service_kw in combined and version_kw in combined:
            ha.outdated_services.append(
                OutdatedService(
                    port=port.port,
                    service=port.display_service,
                    version=port.version_string,
                    advisory=advisory,
                )
            )
            ha.findings.append(
                Finding(
                    severity="HIGH",
                    title=f"Potentially vulnerable version on port {port.port}",
                    detail=advisory,
                )
            )


def _check_script_output(port: PortInfo, ha: HostAnalysis) -> None:
    """Parse NSE script output for known indicators."""

    for script_id, output in port.script_output.items():
        output_lower = output.lower()

        # Anonymous FTP
        if script_id == "ftp-anon" and "anonymous ftp login allowed" in output_lower:
            ha.findings.append(
                Finding(
                    severity="HIGH",
                    title=f"Anonymous FTP login allowed on port {port.port}",
                    detail=output[:200],
                )
            )
            ha.suggestions.append(
                f"Connect via anonymous FTP:  ftp {ha.host.address}  (user: anonymous)"
            )

        # SMB signing disabled / not required
        if "smb2-security-mode" in script_id:
            if "signing enabled and not required" in output_lower:
                ha.findings.append(
                    Finding(
                        severity="MEDIUM",
                        title="SMB signing not required",
                        detail="SMB relay attacks (e.g. Responder) may be possible.",
                    )
                )

        # HTTP server header / title
        if script_id == "http-title":
            ha.findings.append(
                Finding(
                    severity="INFO",
                    title=f"HTTP title on port {port.port}",
                    detail=output[:200],
                )
            )

        # Vuln scripts
        if "VULNERABLE" in output:
            ha.findings.append(
                Finding(
                    severity="CRITICAL",
                    title=f"Vulnerability detected by script '{script_id}' on port {port.port}",
                    detail=output[:500],
                )
            )


def _collect_suggestions(port: PortInfo, ha: HostAnalysis) -> None:
    """Add manual next-step suggestions based on detected service."""
    svc = (port.service or port.product or "").lower().strip()
    target = ha.host.address

    for key, suggestions in SERVICE_SUGGESTIONS.items():
        if key in svc:
            for suggestion in suggestions:
                ha.suggestions.append(suggestion.replace("<target>", target))
            break   # Only use the most specific match


def _check_os_findings(host: HostResult, ha: HostAnalysis) -> None:
    """Add informational findings based on OS detection results."""
    if not host.os_guesses:
        return

    best = host.os_guesses[0]
    if best.accuracy >= 85:
        ha.findings.append(
            Finding(
                severity="INFO",
                title=f"OS fingerprint: {best.name}",
                detail=f"Accuracy: {best.accuracy}% | Family: {best.os_family} | Gen: {best.os_gen}",
            )
        )

    # Windows XP / Server 2003 — EOL
    name_lower = best.name.lower()
    if "windows xp" in name_lower or "windows server 2003" in name_lower:
        ha.findings.append(
            Finding(
                severity="CRITICAL",
                title="End-of-Life Windows version detected",
                detail=(
                    f"{best.name} is no longer supported by Microsoft. "
                    "Likely vulnerable to MS08-067, MS17-010, and many others."
                ),
            )
        )


def _check_host_scripts(host: HostResult, ha: HostAnalysis) -> None:
    """Flag important host-level script findings."""
    for script_id, output in host.host_scripts.items():
        if "VULNERABLE" in output:
            ha.findings.append(
                Finding(
                    severity="CRITICAL",
                    title=f"Host-level vulnerability from script '{script_id}'",
                    detail=output[:500],
                )
            )
