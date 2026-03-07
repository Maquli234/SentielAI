"""
SentinelAI Extension — Attack Surface Scoring Engine
=====================================================
Produces a refined 0-10 risk score from a HostAnalysis object.
Runs AFTER analyzer.analyze() and feeds into reporting.

Usage:
    from scoring.attack_surface_scorer import AttackSurfaceScorer
    scorer  = AttackSurfaceScorer()
    result  = scorer.score_host(host_analysis)
    print(result)                       # rich text summary
    report_data = result.to_dict()      # for report_generator integration
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analyzer import HostAnalysis

from config import RISKY_PORTS, RISK_WEIGHTS

# ── Weight tables ─────────────────────────────────────────────────────────────
_INSECURE_SERVICES = {
    "telnet": 2.0, "ftp": 1.5, "rsh": 2.0, "rlogin": 2.0, "tftp": 1.5,
    "snmp":   1.2, "http": 0.4,
}
_ANONYMOUS_PHRASES = {
    "anonymous ftp login allowed": 2.0,
    "anonymous login":             1.8,
    "null session":                1.5,
    "guest access":                1.3,
    "unauthenticated":             1.8,
}
_WEAK_TLS_TOKENS = [
    "sslv2","sslv3","tlsv1.0","tlsv1.1",
    "rc4","des","3des","export","null cipher","md5",
]
_SEVERITY_MAP = [(9.0,"CRITICAL"),(7.0,"HIGH"),(5.0,"MEDIUM"),(3.0,"LOW"),(0.0,"INFO")]


@dataclass
class ScoringResult:
    target:     str
    risk_score: float
    severity:   str
    reasons:    list[str]
    breakdown:  dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":     self.target,
            "risk_score": round(self.risk_score, 2),
            "severity":   self.severity,
            "reasons":    self.reasons,
            "breakdown":  {k: round(v, 2) for k, v in self.breakdown.items()},
        }

    def __str__(self) -> str:
        bar = chr(9472) * 52
        sev_colours = {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow",     "LOW": "green", "INFO": "dim"
        }
        colour = sev_colours.get(self.severity, "white")
        lines = [
            "",
            bar,
            f"  Attack Surface Score : {self.risk_score:.1f} / 10  [{self.severity}]",
            f"  Target               : {self.target}",
            bar,
            "  Risk Factors:",
        ]
        for r in self.reasons:
            lines.append("    " + chr(8226) + " " + r)
        lines.append(bar + "")
        return "\n".join(lines)

    def rich_panel(self) -> str:
        """Return a Rich-markup string for use with assistant.py render helpers."""
        colour = {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"
        }.get(self.severity, "white")
        lines = [
            f"[{colour}]Score: {self.risk_score:.1f} / 10  [{self.severity}][/{colour}]",
        ]
        for r in self.reasons:
            lines.append(f"  [{colour}]•[/{colour}] {r}")
        return "\n".join(lines)


class AttackSurfaceScorer:
    """
    Score a HostAnalysis object produced by analyzer.analyze().
    Falls back gracefully if optional fields are missing.
    """

    def score_host(self, ha: "HostAnalysis") -> ScoringResult:
        host    = ha.host
        target  = host.address
        ports   = host.open_ports
        raw     = 0.0
        reasons: list[str] = []
        bd: dict[str, float] = {}

        # ── 1. Risky ports (reuse config.RISKY_PORTS) ─────────────────
        rp_score = 0.0
        for p in ports:
            if p.port in RISKY_PORTS:
                data = RISKY_PORTS[p.port]
                w = {"CRITICAL": RISK_WEIGHTS["critical_port"],
                     "HIGH":     RISK_WEIGHTS["high_port"],
                     "MEDIUM":   RISK_WEIGHTS["medium_port"]}.get(data["risk"], 0.5)
                rp_score += w
                reasons.append(f"exposed {data['service']} (port {p.port}, {data['risk']})")
        bd["risky_ports"] = min(rp_score, 5.0); raw += bd["risky_ports"]

        # ── 2. Insecure cleartext protocols ───────────────────────────
        ip_score = 0.0
        for p in ports:
            svc = (p.service + p.product).lower()
            for proto, w in _INSECURE_SERVICES.items():
                if proto in svc:
                    ip_score += w
                    reasons.append(f"insecure protocol: {proto.upper()} on port {p.port}")
                    break
        bd["insecure_protocols"] = min(ip_score, 3.0); raw += bd["insecure_protocols"]

        # ── 3. Outdated services (from ha.outdated) ───────────────────
        od_score = 0.0
        for od in ha.outdated:
            w = RISK_WEIGHTS["outdated_version"]
            if od.severity == "CRITICAL": w *= 1.4
            od_score += w
            reasons.append(f"outdated: {od.service} {od.version}")
        bd["outdated_versions"] = min(od_score, 4.0); raw += bd["outdated_versions"]

        # ── 4. Anonymous / open access (from NSE script output) ───────
        an_score = 0.0
        all_script_out = " ".join(
            s.output.lower()
            for p in ports for s in p.scripts
        )
        for phrase, w in _ANONYMOUS_PHRASES.items():
            if phrase in all_script_out:
                an_score += w
                reasons.append(f"open/anonymous access: {phrase}")
        bd["anonymous_access"] = min(an_score, 3.0); raw += bd["anonymous_access"]

        # ── 5. CVE / vulnerability script hits ────────────────────────
        cve_score = 0.0
        cves_found: list[str] = []
        for f in ha.findings:
            cves = re.findall(r"CVE-[0-9]{4}-[0-9]+", f.title + (f.detail or ""))
            cves_found.extend(cves)
            if f.severity == "CRITICAL": cve_score += RISK_WEIGHTS["vuln_script_hit"]
            elif f.severity == "HIGH":   cve_score += RISK_WEIGHTS["anon_service"]
        cves_found = list(dict.fromkeys(cves_found))
        if cves_found:
            reasons.append(f"{len(cves_found)} CVE(s): {', '.join(cves_found[:5])}")
        bd["cves"] = min(cve_score, 4.0); raw += bd["cves"]

        # ── 6. Weak TLS (from ssl-* script output) ────────────────────
        tls_text = " ".join(
            s.output.lower() for p in ports
            if p.tunnel == "ssl" or p.port in (443, 8443)
            for s in p.scripts
        )
        tls_flags = [t for t in _WEAK_TLS_TOKENS if t in tls_text]
        tw = len(tls_flags) * 0.5
        if tls_flags:
            reasons.append(f"weak TLS: {', '.join(t.upper() for t in tls_flags[:4])}")
        bd["weak_tls"] = min(tw, 2.0); raw += bd["weak_tls"]

        # ── 7. Port count penalty ──────────────────────────────────────
        excess = max(0, len(ports) - 10)
        ps = min(excess * 0.05, 1.0)
        if ps: reasons.append(f"large attack surface: {len(ports)} open ports")
        bd["port_count"] = ps; raw += ps

        # ── Normalise ──────────────────────────────────────────────────
        score    = min(round(raw / 2.0, 1), 10.0)
        severity = next(s for t, s in _SEVERITY_MAP if score >= t)
        if not reasons:
            reasons.append("No significant risk factors detected")

        return ScoringResult(target=target, risk_score=score,
                             severity=severity, reasons=reasons, breakdown=bd)
