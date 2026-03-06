"""
SentinelAI CLI Module
======================
Interactive terminal dashboard built with prompt_toolkit and Rich.

Provides:
• Auto-completing command prompt
• Command history (↑ / ↓)
• Rich-formatted help and output
• Scan orchestration (calls scanner → parser → analyzer → assistant)
• Inline scan progress display
"""

import argparse
import logging
import shlex
import sys
from pathlib import Path
from typing import Optional

from prompt_toolkit              import PromptSession
from prompt_toolkit.completion   import WordCompleter
from prompt_toolkit.styles       import Style as PTStyle
from prompt_toolkit.formatted_text import HTML
from rich.console                import Console
from rich.panel                  import Panel
from rich.table                  import Table
from rich.text                   import Text
from rich.rule                   import Rule
from rich.progress               import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
)
from rich import box

import scanner
import parser as nmap_parser
import analyzer
import assistant
from config import (
    TOOL_NAME, TOOL_VERSION, DISCLAIMER,
    SCAN_PROFILES, SCANS_DIR, LOGS_DIR
)

logger  = logging.getLogger("sentinelai.cli")
console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Prompt style
# ─────────────────────────────────────────────────────────────────────────────

PT_STYLE = PTStyle.from_dict({
    "prompt":    "bold ansicyan",
    "rprompt":   "ansigray",
})

COMMANDS = [
    "scan", "quickscan", "fullscan", "osscan", "vulnscan",
    "ports", "stealthscan", "analyze", "help", "exit", "quit",
    "clear", "scans",
]

COMPLETER = WordCompleter(COMMANDS, ignore_case=True)


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
[bold cyan]
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝
[/bold cyan]
[bold white]                  R E C O N   A S S I S T A N T[/bold white]
[dim]                       v{TOOL_VERSION}  |  Educational use only[/dim]
"""

HELP_TEXT = """
[bold cyan]Available Commands[/bold cyan]

  [bold green]scan[/bold green] <target> [options]          Full scan (SYN + version detection)
  [bold green]quickscan[/bold green] <target> [options]     Fast top-100 port scan (-T4 -F)
  [bold green]fullscan[/bold green] <target> [options]      All ports scan (-sS -sV -p-)
  [bold green]osscan[/bold green] <target> [options]        OS detection (-O)
  [bold green]vulnscan[/bold green] <target> [options]      Vulnerability scripts (--script vuln)
  [bold green]stealthscan[/bold green] <target> [options]   Stealth SYN scan (-sS -Pn)
  [bold green]ports[/bold green] <target> [options]         Service + default scripts (-sV --script default)
  [bold green]analyze[/bold green] <xml_file>               Parse & analyse a saved XML scan file

  [bold green]scans[/bold green]                            List saved scan files
  [bold green]help[/bold green]                             Show this help
  [bold green]clear[/bold green]                            Clear the screen
  [bold green]exit[/bold green]                             Exit SentinelAI

[bold cyan]Scan Options[/bold cyan]

  --ports <range>        Custom port range  e.g. 1-1000 or 22,80,443
  --speed <T0–T5>        Nmap timing template (T0=slowest, T5=fastest)
  --scripts <list>       Comma-separated NSE scripts  e.g. http-title,ftp-anon
  --output <name>        Base name for output files

[bold cyan]Examples[/bold cyan]

  [dim]SentinelAI>[/dim] scan 192.168.1.10
  [dim]SentinelAI>[/dim] quickscan 10.10.10.5 --ports 1-1000 --speed T3
  [dim]SentinelAI>[/dim] vulnscan 10.0.0.1 --ports 21,22,80,445
  [dim]SentinelAI>[/dim] analyze scans/192.168.1.10_full_20240101_120000.xml

[bold red]⚠  This tool is for authorised penetration testing labs ONLY.[/bold red]
[bold red]   Never scan systems without explicit written permission.[/bold red]
"""


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser for inline options
# ─────────────────────────────────────────────────────────────────────────────

def _build_option_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    p.add_argument("--ports",   default=None)
    p.add_argument("--speed",   default=None)
    p.add_argument("--scripts", default=None)
    p.add_argument("--output",  default=None)
    return p

_OPTION_PARSER = _build_option_parser()


def _parse_options(tokens: list[str]) -> tuple[list[str], dict]:
    """
    Split *tokens* into positional args and named options.
    Returns (positionals, options_dict).
    """
    positionals = []
    flags       = []
    i = 0
    while i < len(tokens):
        if tokens[i].startswith("--"):
            flags.append(tokens[i])
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                flags.append(tokens[i + 1])
                i += 2
            else:
                i += 1
        else:
            positionals.append(tokens[i])
            i += 1

    try:
        ns, _ = _OPTION_PARSER.parse_known_args(flags)
        opts = vars(ns)
    except Exception:
        opts = {}

    return positionals, opts


# ─────────────────────────────────────────────────────────────────────────────
# Scan orchestration
# ─────────────────────────────────────────────────────────────────────────────

_COMMAND_TO_PROFILE = {
    "scan":        "full",
    "quickscan":   "quick",
    "fullscan":    "full",
    "osscan":      "os",
    "vulnscan":    "vuln",
    "stealthscan": "stealth",
    "ports":       "ports",
}


def _run_and_analyze(target: str, profile: str, opts: dict) -> None:
    """Execute a scan, parse the result, and render analysis."""

    profile_info = SCAN_PROFILES[profile]
    console.print()
    console.print(
        Panel(
            f"[bold]Target :[/bold] [cyan]{target}[/cyan]\n"
            f"[bold]Profile:[/bold] {profile_info['label']}\n"
            f"[bold]Info   :[/bold] {profile_info['description']}",
            title="[bold yellow]  INITIATING SCAN  [/bold yellow]",
            border_style="yellow",
        )
    )

    # Progress spinner
    scan_result_dict: dict = {}

    with Progress(
        SpinnerColumn(spinner_name="dots2"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Running {profile_info['label']}…[/cyan]", total=None
        )

        def _callback(msg: str) -> None:
            progress.update(task, description=f"[dim]{msg[:60]}[/dim]")

        scan_result_dict = scanner.run_scan(
            target=target,
            profile=profile,
            ports=opts.get("ports"),
            speed=opts.get("speed"),
            scripts=opts.get("scripts"),
            progress_callback=_callback,
        )

    # ── Handle errors ────────────────────────────────────────────────────────
    if not scan_result_dict.get("success"):
        err = scan_result_dict.get("error", "Unknown error")
        assistant.render_scan_error(err)
        # Print stderr if different from error
        stderr = scan_result_dict.get("stderr", "")
        if stderr and stderr != err:
            console.print(f"  [dim]{stderr[:400]}[/dim]")
        return

    xml_path = scan_result_dict.get("xml_path")
    if not xml_path:
        assistant.render_warning("Scan completed but no XML output found.")
        console.print(scan_result_dict.get("stdout", ""))
        return

    assistant.render_success(f"Scan complete. Results saved → {xml_path}")

    # ── Parse & analyse ───────────────────────────────────────────────────────
    try:
        parsed = nmap_parser.parse_xml(xml_path)
    except Exception as exc:
        assistant.render_scan_error(f"Failed to parse XML: {exc}")
        return

    if not parsed.hosts:
        assistant.render_warning("No hosts in scan results (target may be down or filtered).")
        return

    report = analyzer.analyze(parsed)
    assistant.render_report(report)


# ─────────────────────────────────────────────────────────────────────────────
# Individual command handlers
# ─────────────────────────────────────────────────────────────────────────────

def cmd_scan(args: list[str], profile_override: Optional[str] = None) -> None:
    positionals, opts = _parse_options(args)
    if not positionals:
        assistant.render_warning("Usage: scan <target> [--ports <range>] [--speed <T0-T5>]")
        return
    target  = positionals[0]
    profile = profile_override or "full"
    _run_and_analyze(target, profile, opts)


def cmd_analyze(args: list[str]) -> None:
    if not args:
        assistant.render_warning("Usage: analyze <path_to_xml_file>")
        return

    xml_path = Path(args[0])
    if not xml_path.is_absolute():
        # Try relative to CWD, then relative to SCANS_DIR
        if not xml_path.exists():
            xml_path = SCANS_DIR / args[0]

    if not xml_path.exists():
        assistant.render_scan_error(f"File not found: {xml_path}")
        return

    console.print(f"\n  [cyan]Parsing:[/cyan] {xml_path}\n")
    try:
        parsed = nmap_parser.parse_xml(xml_path)
    except Exception as exc:
        assistant.render_scan_error(str(exc))
        return

    report = analyzer.analyze(parsed)
    assistant.render_report(report)


def cmd_scans(_args: list[str]) -> None:
    """List saved scan files."""
    files = sorted(SCANS_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        assistant.render_info(f"No saved scans found in {SCANS_DIR}/")
        return

    table = Table(
        title="Saved Scan Files",
        box=box.SIMPLE,
        header_style="bold magenta",
    )
    table.add_column("#",        width=4,  style="dim")
    table.add_column("Filename", style="cyan")
    table.add_column("Size",     width=10, style="white")
    table.add_column("Modified", style="dim")

    import datetime
    for i, f in enumerate(files, 1):
        stat = f.stat()
        modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        size_kb   = stat.st_size / 1024
        table.add_row(
            str(i),
            f.name,
            f"{size_kb:.1f} KB",
            modified,
        )

    console.print(table)


def cmd_help(_args: list[str]) -> None:
    console.print(Panel(HELP_TEXT, border_style="cyan", padding=(1, 2)))


def cmd_clear(_args: list[str]) -> None:
    console.clear()
    console.print(BANNER)


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch table
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch(line: str) -> bool:
    """
    Parse and dispatch a command line.
    Returns False if the user wants to exit, True otherwise.
    """
    line = line.strip()
    if not line:
        return True

    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        assistant.render_warning(f"Parse error: {exc}")
        return True

    command = tokens[0].lower()
    rest    = tokens[1:]

    if command in ("exit", "quit"):
        console.print("\n[dim]Goodbye. Stay ethical.[/dim]\n")
        return False

    elif command in _COMMAND_TO_PROFILE:
        profile = _COMMAND_TO_PROFILE[command]
        cmd_scan(rest, profile_override=profile)

    elif command == "analyze":
        cmd_analyze(rest)

    elif command == "scans":
        cmd_scans(rest)

    elif command in ("help", "?"):
        cmd_help(rest)

    elif command == "clear":
        cmd_clear(rest)

    else:
        assistant.render_warning(
            f"Unknown command: '{command}'.  Type [bold]help[/bold] for available commands."
        )

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

def run() -> None:
    # Print banner and disclaimer
    console.print(BANNER)
    console.print(
        Panel(
            f"[bold red]{DISCLAIMER}[/bold red]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()
    console.print("  Type [bold cyan]help[/bold cyan] for available commands.\n")

    session: PromptSession = PromptSession(
        completer=COMPLETER,
        style=PT_STYLE,
        history=None,   # In-memory history only
    )

    while True:
        try:
            line = session.prompt(
                HTML("<prompt>SentinelAI</prompt><b> ❯ </b>"),
                style=PT_STYLE,
            )
        except KeyboardInterrupt:
            console.print("\n  [dim]Use [bold]exit[/bold] to quit.[/dim]")
            continue
        except EOFError:
            console.print("\n[dim]EOF received. Exiting.[/dim]\n")
            break

        should_continue = _dispatch(line)
        if not should_continue:
            break
