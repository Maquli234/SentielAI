"""
SentinelAI Output Module
=========================
Rich-formatted terminal renderers.
LLM analysis delegated to ai.llm_reasoning when --ai flag is used.
"""

import logging
from typing import Optional

from rich.console  import Console
from rich.panel    import Panel
from rich.table    import Table
from rich.text     import Text
from rich.rule     import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich          import box

from core.analyzer import AnalysisReport, HostAnalysis
from config        import TOOL_NAME

logger  = logging.getLogger("sentinelai.core.output")
console = Console()

SEV_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "bright_black",
}
RISK_COLOUR = {
    "CRITICAL":      "bold red",
    "HIGH":          "red",
    "MEDIUM":        "yellow",
    "LOW":           "green",
    "INFORMATIONAL": "bright_black",
}


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


def _render_host(ha: HostAnalysis) -> None:
    host = ha.host

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

    if host.os_guesses:
        best   = host.os_guesses[0]
        filled = int(best.accuracy / 10)
        bar    = "█" * filled + "░" * (10 - filled)
        colour = "green" if best.accuracy >= 80 else "yellow"
        console.print(f"  [bold]OS:[/bold]  [{colour}]{bar}[/{colour}]  {best.accuracy}%  {best.name}")
        console.print()

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

    if ha.risk_score and ha.risk_score.factors:
        console.print("  [bold red]Risk Factors[/bold red]")
        for factor in ha.risk_score.factors[:6]:
            console.print(f"    [red]•[/red] {factor}")
        console.print()

    if ha.outdated:
        console.print("  [bold red]🔥  Potentially Vulnerable Versions[/bold red]")
        for od in ha.outdated:
            c = SEV_COLOUR.get(od.severity, "white")
            console.print(f"    [{c}][{od.severity}][/{c}]  Port {od.port}  {od.version}")
            console.print(f"      [dim]{od.advisory}[/dim]")
        console.print()

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


def _render_llm_analysis(report: AnalysisReport) -> None:
    from ai.llm_reasoning import LLMReasoningModule
    from config import ANTHROPIC_API_KEY, LLM_MODEL

    console.print(Rule("[bold magenta]  AI THREAT ANALYSIS  [/bold magenta]", style="magenta"))

    with Progress(
        SpinnerColumn(), TextColumn("[magenta]Requesting AI analysis…"), TimeElapsedColumn(),
        console=console, transient=True,
    ) as progress:
        progress.add_task("", total=None)
        llm = LLMReasoningModule(backend="anthropic", api_key=ANTHROPIC_API_KEY, model=LLM_MODEL)
        responses: list[str] = []
        for ha in report.host_analyses[:3]:
            recs = llm.analyze(ha)
            responses.extend(recs)

    if responses:
        console.print(Panel(
            "\n".join(f"  {i+1}. {r}" for i, r in enumerate(responses[:20])),
            title="[bold magenta]  Claude AI Analysis  [/bold magenta]",
            border_style="magenta", padding=(1, 2),
        ))
    else:
        console.print(
            "  [dim]AI analysis unavailable (network error or API not configured).[/dim]\n"
            "  [dim]Set ANTHROPIC_API_KEY environment variable.[/dim]"
        )


# ── Utility renders ────────────────────────────────────────────────────────────

def render_error(msg: str) -> None:
    console.print(Panel(f"[red]{msg}[/red]", title="[bold red]Error[/bold red]", border_style="red"))

def render_info(msg: str) -> None:
    console.print(f"  [cyan]ℹ[/cyan]  {msg}")

def render_warning(msg: str) -> None:
    console.print(f"  [yellow]⚠[/yellow]  {msg}")

def render_success(msg: str) -> None:
    console.print(f"  [green]✓[/green]  {msg}")
