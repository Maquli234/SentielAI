"""
SentinelAI Report Generator
==============================
Generates security reports in:
  • Markdown (.md)
  • HTML (.html)
  • JSON (.json)

Inputs: AnalysisReport from analyzer.py
Output: file path to generated report
"""

import json
import datetime
import logging
from pathlib import Path
from typing import Optional

from config import REPORTS_DIR, TOOL_NAME, TOOL_VERSION
from analyzer import AnalysisReport, HostAnalysis

logger = logging.getLogger("sentinelai.report")


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────────────────────────────────────
# Markdown
# ─────────────────────────────────────────────────────────────────────────────

def generate_markdown(report: AnalysisReport, filename: Optional[str] = None) -> Path:
    lines = []
    lines.append(f"# {TOOL_NAME} — Security Assessment Report")
    lines.append(f"\n**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Tool Version:** {TOOL_VERSION}  ")
    lines.append(f"**Scan Command:** `{report.scan_command}`  ")
    lines.append(f"**Scan Time:** {report.scan_time}\n")
    lines.append("---\n")
    lines.append("> ⚠ This report is for authorized security testing only.\n")
    lines.append("---\n")

    # Executive summary
    total_hosts   = len(report.host_analyses)
    critical_hosts = sum(
        1 for ha in report.host_analyses
        if ha.risk_score and ha.risk_score.label in ("CRITICAL", "HIGH")
    )
    lines.append("## Executive Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Hosts Assessed | {total_hosts} |")
    lines.append(f"| High/Critical Risk Hosts | {critical_hosts} |")
    lines.append(f"| Total Findings | {sum(len(ha.findings) for ha in report.host_analyses)} |")
    lines.append("")

    # Per-host sections
    for ha in report.host_analyses:
        host = ha.host
        lines.append(f"\n---\n\n## Host: {host.display_name}")
        if ha.risk_score:
            lines.append(f"\n**Risk Score:** {ha.risk_score.score}/10 ({ha.risk_score.label})\n")

        # OS
        if host.best_os:
            lines.append(f"**OS:** {host.best_os.name} ({host.best_os.accuracy}%)\n")

        # Open ports table
        if host.open_ports:
            lines.append("### Open Ports\n")
            lines.append("| Port | Protocol | Service | Version |")
            lines.append("|------|----------|---------|---------|")
            for p in host.open_ports:
                lines.append(f"| {p.port} | {p.protocol} | {p.display_service} | {p.version_string or '—'} |")
            lines.append("")

        # Risky ports
        if ha.risky_ports:
            lines.append("### Risky Ports\n")
            for rp in ha.risky_ports:
                lines.append(f"- **[{rp.risk}]** Port {rp.port} ({rp.service}) — {rp.category}")
            lines.append("")

        # Outdated services
        if ha.outdated:
            lines.append("### Outdated / Vulnerable Services\n")
            for od in ha.outdated:
                lines.append(f"- **[{od.severity}]** Port {od.port} `{od.version}` — {od.advisory}")
            lines.append("")

        # Findings
        if ha.findings:
            lines.append("### Analysis Findings\n")
            for f in ha.findings:
                lines.append(f"- **[{f.severity}]** {f.title}")
                if f.detail and f.detail != f.title:
                    lines.append(f"  > {f.detail[:200]}")
            lines.append("")

        # Suggestions
        if ha.suggestions:
            lines.append("### Suggested Next Steps\n")
            for s in ha.suggestions[:12]:
                lines.append(f"```\n{s}\n```")
            lines.append("")

    out_path = REPORTS_DIR / (filename or f"report_{_ts()}.md")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Markdown report → %s", out_path)
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# JSON
# ─────────────────────────────────────────────────────────────────────────────

def generate_json(report: AnalysisReport, filename: Optional[str] = None) -> Path:
    data = {
        "tool":        TOOL_NAME,
        "version":     TOOL_VERSION,
        "generated":   datetime.datetime.now().isoformat(),
        "scan_command": report.scan_command,
        "scan_time":   report.scan_time,
        "hosts": [],
    }

    for ha in report.host_analyses:
        host = ha.host
        host_data = {
            "address":    host.address,
            "hostname":   host.hostname,
            "state":      host.state,
            "mac":        host.mac_address,
            "os":         {"name": host.best_os.name, "accuracy": host.best_os.accuracy}
                          if host.best_os else None,
            "risk_score": {"score": ha.risk_score.score, "label": ha.risk_score.label,
                           "factors": ha.risk_score.factors}
                          if ha.risk_score else None,
            "open_ports": [
                {
                    "port":     p.port,
                    "protocol": p.protocol,
                    "service":  p.display_service,
                    "version":  p.version_string,
                    "scripts":  {s.script_id: s.output[:200] for s in p.scripts},
                }
                for p in host.open_ports
            ],
            "risky_ports": [
                {"port": rp.port, "service": rp.service, "risk": rp.risk}
                for rp in ha.risky_ports
            ],
            "outdated_services": [
                {"port": od.port, "service": od.service, "version": od.version,
                 "severity": od.severity, "advisory": od.advisory}
                for od in ha.outdated
            ],
            "findings": [
                {"severity": f.severity, "title": f.title, "detail": f.detail, "port": f.port}
                for f in ha.findings
            ],
            "suggestions": ha.suggestions[:15],
            "attack_vectors": ha.attack_vectors,
        }
        data["hosts"].append(host_data)

    out_path = REPORTS_DIR / (filename or f"report_{_ts()}.json")
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    logger.info("JSON report → %s", out_path)
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

def generate_html(report: AnalysisReport, filename: Optional[str] = None) -> Path:
    SEVERITY_COLOURS = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#00aaff",
        "INFO":     "#888888",
    }

    def badge(sev: str) -> str:
        c = SEVERITY_COLOURS.get(sev, "#888")
        return f'<span style="background:{c};color:#000;padding:2px 7px;border-radius:3px;font-size:0.75em;font-weight:700">{sev}</span>'

    rows = []
    for ha in report.host_analyses:
        host  = ha.host
        score = ha.risk_score.score if ha.risk_score else 0
        label = ha.risk_score.label if ha.risk_score else "?"
        lc    = SEVERITY_COLOURS.get(label, "#888")

        port_rows = "".join(
            f"<tr><td>{p.port}/{p.protocol}</td><td>{p.display_service}</td>"
            f"<td>{p.version_string or '—'}</td></tr>"
            for p in host.open_ports
        )

        finding_items = "".join(
            f"<li>{badge(f.severity)} {f.title}"
            + (f"<br><small style='color:#aaa'>{f.detail[:150]}</small>" if f.detail else "")
            + "</li>"
            for f in ha.findings[:10]
        )

        suggestion_items = "".join(
            f"<li><code>{s}</code></li>" for s in ha.suggestions[:10]
        )

        rows.append(f"""
<div class="host-card">
  <div class="host-header">
    <span class="host-addr">{host.display_name}</span>
    <span class="risk-badge" style="background:{lc}">{score}/10 {label}</span>
  </div>
  {"<p class='os-info'>OS: " + host.best_os.name + f" ({host.best_os.accuracy}%)</p>" if host.best_os else ""}
  <h3>Open Ports</h3>
  <table class="port-table">
    <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>
  <h3>Findings</h3>
  <ul class="findings">{finding_items}</ul>
  <h3>Suggested Next Steps</h3>
  <ul class="suggestions">{suggestion_items}</ul>
</div>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{TOOL_NAME} Report</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0d0d0d; color: #e0e0e0; margin: 0; padding: 20px; }}
h1 {{ color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }}
h2 {{ color: #00ccff; }}
h3 {{ color: #aaa; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }}
.host-card {{ background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 20px; margin: 20px 0; }}
.host-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
.host-addr {{ font-size: 1.3em; font-weight: bold; color: #00ffcc; }}
.risk-badge {{ padding: 4px 12px; border-radius: 4px; color: #000; font-weight: 700; font-size: 0.9em; }}
.os-info {{ color: #888; font-size: 0.85em; }}
.port-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
.port-table th {{ background: #222; text-align: left; padding: 8px; color: #00ccff; }}
.port-table td {{ padding: 6px 8px; border-bottom: 1px solid #2a2a2a; }}
.port-table tr:hover td {{ background: #1f1f1f; }}
.findings li {{ margin: 5px 0; }}
.suggestions code {{ background: #0f0f0f; color: #00ff88; padding: 3px 8px; border-radius: 3px; font-size: 0.85em; display: block; margin: 3px 0; }}
.meta {{ color: #555; font-size: 0.8em; margin-bottom: 20px; }}
.disclaimer {{ background: #1a0000; border: 1px solid #ff4444; padding: 10px; border-radius: 4px; color: #ff6666; margin: 15px 0; }}
</style>
</head>
<body>
<h1>🛡 {TOOL_NAME} — Security Assessment Report</h1>
<div class="meta">
  Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
  Tool: {TOOL_NAME} v{TOOL_VERSION} |
  Command: <code>{report.scan_command}</code>
</div>
<div class="disclaimer">
  ⚠ This report is for authorized penetration testing and educational lab use only.
</div>
{"".join(rows)}
</body>
</html>"""

    out_path = REPORTS_DIR / (filename or f"report_{_ts()}.html")
    out_path.write_text(html, encoding="utf-8")
    logger.info("HTML report → %s", out_path)
    return out_path


def generate_all(report: AnalysisReport, base_name: Optional[str] = None) -> dict[str, Path]:
    ts   = base_name or _ts()
    return {
        "markdown": generate_markdown(report, f"report_{ts}.md"),
        "json":     generate_json(report,     f"report_{ts}.json"),
        "html":     generate_html(report,     f"report_{ts}.html"),
    }
