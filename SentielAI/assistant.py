"""
SentinelAI Assistant Module
============================
Converts an AnalysisReport into human-readable, Rich-formatted output.

This module is purely presentational — it formats and prints findings.
It does NOT execute any commands or make network connections.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.rule import Rule
from rich.columns import Columns
from rich.padding import Padding

from analyzer import AnalysisReport, HostAnalysis, Finding
from parser import HostResult

console = Console()

# Severity → Rich colour
SEVERITY_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "bright_black",
}

RISK_COLOUR = {
    "HIGH":   "red",
    "MEDIUM": "yellow",
    "LOW":    "green",
}


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def render_report(report: AnalysisReport) -> None:
    """Print the full analysis report to the terminal."""

    console.print()
    console.print(
        Rule("[bold cyan]  SCAN ANALYSIS REPORT  [/bold cyan]", style="cyan")
    )
    if report.scan_time:
        console.print(f"  [dim]Scan time : {report.scan_time}[/dim]")
    if report.scan_command:
        console.print(f"  [dim]Command   : {report.scan_command}[/dim]")
    console.print()

    if not report.host_analyses:
        console.print("  [yellow]No hosts found in scan results.[/yellow]")
        return

    for ha in report.host_analyses:
        _render_host(ha)
        console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Per-host rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render_host(ha: HostAnalysis) -> None:
    host = ha.host

    # ── Host header ──────────────────────────────────────────────────────────
    label = host.address
    if host.hostname:
        label += f"  ({host.hostname})"
    if host.mac_address:
        label += f"  [dim]MAC: {host.mac_address}"
        if host.mac_vendor:
            label += f" / {host.mac_vendor}"
        label += "[/dim]"

    console.print(
        Panel(
            f"[bold white]{label}[/bold white]",
            title="[bold cyan]TARGET HOST[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )

    # ── Open ports table ──────────────────────────────────────────────────────
    open_ports = host.open_ports
    if open_ports:
        table = Table(
            title="Open Ports",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold magenta",
            title_style="bold white",
        )
        table.add_column("PORT",    style="bold cyan",  width=10)
        table.add_column("PROTO",   style="dim",        width=6)
        table.add_column("STATE",   style="green",      width=8)
        table.add_column("SERVICE", style="yellow",     width=18)
        table.add_column("VERSION", style="white")

        for p in open_ports:
            risk_port = any(rp.port == p.port for rp in ha.risky_ports)
            port_style = "bold red" if risk_port else "bold cyan"

            table.add_row(
                Text(str(p.port), style=port_style),
                p.protocol,
                p.state,
                p.display_service,
                p.version_string or "[dim]—[/dim]",
            )

            # Script output inline
            for script_id, script_out in p.script_output.items():
                short_out = script_out.replace("\n", " ")[:80]
                table.add_row(
                    "",
                    "",
                    "",
                    f"[dim italic]  └─ {script_id}[/dim italic]",
                    f"[dim]{short_out}[/dim]",
                )

        console.print(table)
    else:
        console.print("  [dim]No open ports detected.[/dim]")

    # ── OS guesses ────────────────────────────────────────────────────────────
    if host.os_guesses:
        console.print("  [bold]OS Detection:[/bold]")
        for og in host.os_guesses[:3]:   # Show top-3 guesses
            bar_filled = int(og.accuracy / 10)
            bar = "█" * bar_filled + "░" * (10 - bar_filled)
            colour = "green" if og.accuracy >= 85 else "yellow" if og.accuracy >= 60 else "red"
            console.print(
                f"    [{colour}]{bar}[/{colour}]  {og.accuracy}%  {og.name}"
            )
        console.print()

    # ── Risky ports ───────────────────────────────────────────────────────────
    if ha.risky_ports:
        console.print("  [bold red]⚠  Risky Ports Detected[/bold red]")
        for rp in ha.risky_ports:
            colour = RISK_COLOUR.get(rp.risk, "white")
            console.print(
                f"    [{colour}][{rp.risk}][/{colour}]  "
                f"[bold]{rp.port}/tcp  {rp.service}[/bold]  — {rp.note}"
            )
        console.print()

    # ── Outdated / vulnerable versions ───────────────────────────────────────
    if ha.outdated_services:
        console.print("  [bold red]🔥  Potentially Vulnerable Services[/bold red]")
        for os_svc in ha.outdated_services:
            console.print(
                f"    [red]•[/red] Port {os_svc.port} [{os_svc.service}]  {os_svc.version}"
            )
            console.print(f"      [dim]{os_svc.advisory}[/dim]")
        console.print()

    # ── Findings ──────────────────────────────────────────────────────────────
    critical_or_high = [
        f for f in ha.findings if f.severity in ("CRITICAL", "HIGH")
    ]
    medium_or_below = [
        f for f in ha.findings if f.severity not in ("CRITICAL", "HIGH")
    ]

    if critical_or_high or medium_or_below:
        console.print("  [bold]Analysis Findings[/bold]")
        for finding in critical_or_high + medium_or_below:
            colour = SEVERITY_COLOUR.get(finding.severity, "white")
            console.print(
                f"    [{colour}][{finding.severity}][/{colour}]  [bold]{finding.title}[/bold]"
            )
            if finding.detail and finding.detail != finding.title:
                short_detail = finding.detail[:200].replace("\n", " ")
                console.print(f"      [dim]{short_detail}[/dim]")
        console.print()

    # ── Suggested next steps ──────────────────────────────────────────────────
    if ha.suggestions:
        console.print(
            Panel(
                _format_suggestions(ha.suggestions),
                title="[bold green]  SUGGESTED NEXT STEPS  [/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    else:
        console.print(
            "  [dim]No specific next steps generated for this host.[/dim]"
        )


def _format_suggestions(suggestions: list[str]) -> Text:
    text = Text()
    for i, suggestion in enumerate(suggestions):
        # Bold the command part (before the colon)
        if ":" in suggestion:
            label, _, cmd = suggestion.partition(":")
            text.append(f"  • {label}:\n", style="bold white")
            text.append(f"      {cmd.strip()}\n", style="green")
        else:
            text.append(f"  • {suggestion}\n", style="white")
        if i < len(suggestions) - 1:
            text.append("\n")
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Stand-alone summary (used when there is no full analysis)
# ─────────────────────────────────────────────────────────────────────────────

def render_scan_error(error_msg: str) -> None:
    console.print(
        Panel(
            f"[red]{error_msg}[/red]",
            title="[bold red]Scan Error[/bold red]",
            border_style="red",
        )
    )


def render_info(message: str) -> None:
    console.print(f"  [cyan]ℹ[/cyan]  {message}")


def render_warning(message: str) -> None:
    console.print(f"  [yellow]⚠[/yellow]  {message}")


def render_success(message: str) -> None:
    console.print(f"  [green]✓[/green]  {message}")
