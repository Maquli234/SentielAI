"""
SentinelAI Assistant Module
==============================
• Rich-formatted terminal output renderer
• Optional LLM analysis via Anthropic API (Claude)

The LLM layer sends only scan metadata (no raw packet data) to the model
and receives natural-language analysis + next-step suggestions.
This is purely advisory — no exploitation is performed.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

from rich.console     import Console
from rich.panel       import Panel
from rich.table       import Table
from rich.text        import Text
from rich.rule        import Rule
from rich.progress    import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich             import box

from analyzer         import AnalysisReport, HostAnalysis
from config           import LLM_MODEL, LLM_MAX_TOKENS, TOOL_NAME

logger  = logging.getLogger("sentinelai.assistant")
console = Console()

SEV_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "bright_black",
}
RISK_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFORMATIONAL": "bright_black",
}


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def render_report(report: AnalysisReport, include_llm: bool = False) -> None:
    console.print()
    console.print(Rule("[bold cyan]  SCAN ANALYSIS REPORT  [/bold cyan]", style="cyan"))
    if report.scan_time:
        console.print(f"  [dim]Time   : {report.scan_time}[/dim]")
    if report.scan_command:
        console.print(f"  [dim]Command: {report.scan_command}[/dim]")
    console.print()

    if not report.host_analyses:
        console.print("  [yellow]No hosts found in scan results.[/yellow]")
        return

    for ha in report.host_analyses:
        _render_host(ha)
        console.print()

    if include_llm:
        _render_llm_analysis(report)


# ─────────────────────────────────────────────────────────────────────────────
# Per-host rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render_host(ha: HostAnalysis) -> None:
    host = ha.host

    # Header
    label = host.address
    if host.hostname:
        label += f"  ({host.hostname})"
    score_str = ""
    if ha.risk_score:
        colour = RISK_COLOUR.get(ha.risk_score.label, "white")
        score_str = f"  [{colour}]Risk: {ha.risk_score.score}/10  {ha.risk_score.label}[/{colour}]"

    console.print(Panel(
        f"[bold white]{label}[/bold white]{score_str}",
        title="[bold cyan]TARGET[/bold cyan]",
        border_style="cyan", padding=(0, 1),
    ))

    # OS
    if host.os_guesses:
        best = host.os_guesses[0]
        filled = int(best.accuracy / 10)
        bar = "█" * filled + "░" * (10 - filled)
        colour = "green" if best.accuracy >= 80 else "yellow"
        console.print(
            f"  [bold]OS:[/bold]  [{colour}]{bar}[/{colour}]  {best.accuracy}%  {best.name}"
        )
        console.print()

    # Open ports table
    open_ports = host.open_ports
    if open_ports:
        table = Table(
            title="Open Ports", box=box.SIMPLE_HEAVY,
            header_style="bold magenta", title_style="bold white",
        )
        table.add_column("PORT",    style="bold cyan",  width=8)
        table.add_column("PROTO",   style="dim",        width=6)
        table.add_column("SERVICE", style="yellow",     width=16)
        table.add_column("VERSION", style="white",      min_width=20)

        for p in open_ports:
            is_risky = any(rp.port == p.port for rp in ha.risky_ports)
            port_txt = Text(str(p.port), style="bold red" if is_risky else "bold cyan")
            table.add_row(port_txt, p.protocol, p.display_service,
                          p.version_string or "[dim]—[/dim]")
            for s in p.scripts[:2]:
                short = s.output.replace("\n", " ")[:70]
                table.add_row("", "", f"[dim italic]└─ {s.script_id}[/dim italic]",
                              f"[dim]{short}[/dim]")
        console.print(table)

    # Risk score factors
    if ha.risk_score and ha.risk_score.factors:
        console.print("  [bold red]Risk Factors[/bold red]")
        for factor in ha.risk_score.factors[:6]:
            console.print(f"    [red]•[/red] {factor}")
        console.print()

    # Outdated / vulnerable services
    if ha.outdated:
        console.print("  [bold red]🔥  Potentially Vulnerable Versions[/bold red]")
        for od in ha.outdated:
            c = SEV_COLOUR.get(od.severity, "white")
            console.print(f"    [{c}][{od.severity}][/{c}]  Port {od.port}  {od.version}")
            console.print(f"      [dim]{od.advisory}[/dim]")
        console.print()

    # Findings
    crit_high = [f for f in ha.findings if f.severity in ("CRITICAL", "HIGH")]
    others    = [f for f in ha.findings if f.severity not in ("CRITICAL", "HIGH")]

    if crit_high or others:
        console.print("  [bold]Findings[/bold]")
        for finding in (crit_high + others)[:12]:
            c = SEV_COLOUR.get(finding.severity, "white")
            console.print(f"    [{c}][{finding.severity}][/{c}]  [bold]{finding.title}[/bold]")
            if finding.detail and finding.detail != finding.title:
                console.print(f"      [dim]{finding.detail[:180].replace(chr(10), ' ')}[/dim]")
        console.print()

    # Suggestions
    if ha.suggestions:
        console.print(Panel(
            _format_suggestions(ha.suggestions),
            title="[bold green]  SUGGESTED NEXT STEPS  [/bold green]",
            border_style="green", padding=(0, 1),
        ))


def _format_suggestions(suggestions: list[str]) -> Text:
    text = Text()
    for s in suggestions[:15]:
        if ":" in s:
            label, _, cmd = s.partition(":")
            text.append(f"  • {label}:\n", style="bold white")
            text.append(f"      {cmd.strip()}\n\n", style="green")
        else:
            text.append(f"  • {s}\n\n", style="white")
    return text


# ─────────────────────────────────────────────────────────────────────────────
# LLM Analysis Layer
# ─────────────────────────────────────────────────────────────────────────────

def _build_llm_prompt(report: AnalysisReport) -> str:
    """Build a structured prompt from scan data to send to the LLM."""
    parts = [
        "You are a senior penetration testing consultant reviewing reconnaissance scan results.",
        "Analyze the following data and provide:",
        "1. A concise threat assessment",
        "2. The most critical attack paths to investigate",
        "3. Specific manual testing steps a tester should perform next",
        "4. Any notable misconfigurations or high-value targets",
        "",
        "SCAN DATA:",
    ]

    for ha in report.host_analyses[:3]:  # Limit to first 3 hosts
        host = ha.host
        parts.append(f"\nHost: {host.display_name}")
        if host.best_os:
            parts.append(f"OS: {host.best_os.name} ({host.best_os.accuracy}%)")
        if ha.risk_score:
            parts.append(f"Risk Score: {ha.risk_score.score}/10 ({ha.risk_score.label})")

        parts.append("Open Ports:")
        for p in host.open_ports[:15]:
            parts.append(f"  {p.port}/{p.protocol}  {p.full_label}")

        if ha.outdated:
            parts.append("Outdated/Vulnerable Services:")
            for od in ha.outdated[:5]:
                parts.append(f"  [{od.severity}] {od.advisory}")

        if ha.findings:
            parts.append("Key Findings:")
            for f in [x for x in ha.findings if x.severity in ("CRITICAL", "HIGH")][:5]:
                parts.append(f"  [{f.severity}] {f.title}")

    parts.append(
        "\nIMPORTANT: Only suggest reconnaissance, enumeration, and manual testing approaches. "
        "Do not suggest automated exploitation."
    )

    return "\n".join(parts)


def _call_llm(prompt: str) -> Optional[str]:
    """Call the Anthropic API and return the response text."""
    payload = json.dumps({
        "model": LLM_MODEL,
        "max_tokens": LLM_MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            return "".join(
                block.get("text", "")
                for block in data.get("content", [])
                if block.get("type") == "text"
            )
    except Exception as exc:
        logger.warning("LLM call failed: %s", exc)
        return None


def _render_llm_analysis(report: AnalysisReport) -> None:
    """Request and render LLM-generated analysis."""
    console.print(Rule("[bold magenta]  AI THREAT ANALYSIS  [/bold magenta]", style="magenta"))

    with Progress(
        SpinnerColumn(), TextColumn("[magenta]Requesting AI analysis…"), TimeElapsedColumn(),
        console=console, transient=True,
    ) as progress:
        progress.add_task("", total=None)
        prompt   = _build_llm_prompt(report)
        response = _call_llm(prompt)

    if response:
        console.print(Panel(
            response,
            title="[bold magenta]  Claude AI Analysis  [/bold magenta]",
            border_style="magenta", padding=(1, 2),
        ))
    else:
        console.print(
            "  [dim]AI analysis unavailable (network error or API not configured).[/dim]\n"
            "  [dim]Set ANTHROPIC_API_KEY or run without --ai flag.[/dim]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Utility renders
# ─────────────────────────────────────────────────────────────────────────────

def render_error(msg: str) -> None:
    console.print(Panel(f"[red]{msg}[/red]", title="[bold red]Error[/bold red]", border_style="red"))

def render_info(msg: str) -> None:
    console.print(f"  [cyan]ℹ[/cyan]  {msg}")

def render_warning(msg: str) -> None:
    console.print(f"  [yellow]⚠[/yellow]  {msg}")

def render_success(msg: str) -> None:
    console.print(f"  [green]✓[/green]  {msg}")
