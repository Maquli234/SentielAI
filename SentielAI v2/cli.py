"""
SentinelAI Interactive CLI Dashboard
======================================
prompt_toolkit + Rich interactive terminal with:
  • Tab completion
  • Arrow-key history
  • All scan commands
  • Auto-recon pipeline
  • Report generation
  • Subdomain enumeration
  • Database history
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
from rich.rule                   import Rule
from rich.progress               import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
)
from rich                        import box

import scanner as nmap_scanner
import parser  as nmap_parser
import analyzer
import assistant
from config import (
    TOOL_NAME, TOOL_VERSION, DISCLAIMER,
    SCAN_PROFILES, SCANS_DIR, REPORTS_DIR,
)
from database  import db
from reporting import report_generator

logger  = logging.getLogger("sentinelai.cli")
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Prompt style & completions
# ─────────────────────────────────────────────────────────────────────────────

PT_STYLE = PTStyle.from_dict({"prompt": "bold ansicyan", "rprompt": "ansigray"})

COMMANDS = [
    "scan", "quickscan", "fullscan", "osscan", "vulnscan", "stealthscan",
    "ports", "webscan", "smbscan",
    "subdomains", "analyze", "report", "auto-recon",
    "history", "scans", "help", "clear", "exit", "quit",
]
COMPLETER = WordCompleter(COMMANDS, ignore_case=True)

# ─────────────────────────────────────────────────────────────────────────────
# Banner & help
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
[bold cyan] ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝[/bold cyan]
[bold white]                 ADVANCED RECON ASSISTANT  v{TOOL_VERSION}[/bold white]
[dim]                 Educational / Authorized Lab Use Only[/dim]
"""

HELP_TEXT = """
[bold cyan]Scan Commands[/bold cyan]
  [green]scan[/green] <target> [opts]         Full SYN + version scan
  [green]quickscan[/green] <target> [opts]    Fast top-100 ports
  [green]fullscan[/green] <target> [opts]     All 65535 ports
  [green]osscan[/green] <target> [opts]       OS fingerprinting
  [green]vulnscan[/green] <target> [opts]     NSE vulnerability scripts
  [green]stealthscan[/green] <target> [opts]  SYN scan, skip ping
  [green]ports[/green] <target> [opts]        Service + default scripts
  [green]webscan[/green] <target> [opts]      HTTP/HTTPS focused scripts
  [green]smbscan[/green] <target> [opts]      SMB focused scripts

[bold cyan]Enumeration[/bold cyan]
  [green]subdomains[/green] <domain>          Subdomain enumeration (DNS + CT logs)
  [green]auto-recon[/green] <target> [opts]   Full automated recon pipeline

[bold cyan]Analysis & Reporting[/bold cyan]
  [green]analyze[/green] <xml_file>           Analyse a saved XML scan file
  [green]report[/green] <xml_file> [--format md|html|json|all]   Generate report
  [green]history[/green]                      Show scan database history
  [green]scans[/green]                        List saved scan files

[bold cyan]Scan Options[/bold cyan]
  [dim]--ports <range>     e.g. 1-1000 or 22,80,443
  --speed <T0–T5>     nmap timing template
  --scripts <list>    additional NSE scripts
  --ai                include LLM analysis (requires API key)
  --output <name>     custom output filename[/dim]

[bold cyan]Examples[/bold cyan]
  [dim]SentinelAI ❯[/dim] quickscan 192.168.1.10
  [dim]SentinelAI ❯[/dim] scan 10.10.10.5 --ports 1-1000 --speed T3
  [dim]SentinelAI ❯[/dim] auto-recon 192.168.1.10 --ai
  [dim]SentinelAI ❯[/dim] subdomains example.com
  [dim]SentinelAI ❯[/dim] report scans/192.168.1.10_full.xml --format all

[bold red]⚠  AUTHORIZED TESTING AND EDUCATIONAL LABS ONLY.[/bold red]
"""

# ─────────────────────────────────────────────────────────────────────────────
# Option parser
# ─────────────────────────────────────────────────────────────────────────────

def _build_op() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    p.add_argument("--ports");   p.add_argument("--speed")
    p.add_argument("--scripts"); p.add_argument("--output")
    p.add_argument("--format", default="all")
    p.add_argument("--ai", action="store_true", default=False)
    return p

_OP = _build_op()

def _split_args(tokens: list[str]) -> tuple[list[str], dict]:
    pos, flags, i = [], [], 0
    while i < len(tokens):
        if tokens[i].startswith("--"):
            flags.append(tokens[i])
            if i + 1 < len(tokens) and not tokens[i+1].startswith("--"):
                flags.append(tokens[i+1]); i += 2
            else:
                i += 1
        else:
            pos.append(tokens[i]); i += 1
    try:
        ns, _ = _OP.parse_known_args(flags)
        opts = vars(ns)
    except Exception:
        opts = {}
    return pos, opts


# ─────────────────────────────────────────────────────────────────────────────
# Command → Profile map
# ─────────────────────────────────────────────────────────────────────────────

CMD_PROFILE = {
    "scan":        "full",
    "quickscan":   "quick",
    "fullscan":    "full",
    "osscan":      "os",
    "vulnscan":    "vuln",
    "stealthscan": "stealth",
    "ports":       "ports",
    "webscan":     "web",
    "smbscan":     "smb",
}


# ─────────────────────────────────────────────────────────────────────────────
# Scan orchestration
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan_pipeline(target: str, profile: str, opts: dict) -> Optional[analyzer.AnalysisReport]:
    """Execute scan → parse → analyse → render.  Returns AnalysisReport or None."""
    profile_info = SCAN_PROFILES[profile]
    console.print()
    console.print(Panel(
        f"[bold]Target :[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Profile:[/bold] {profile_info['label']}\n"
        f"[bold]Info   :[/bold] {profile_info['description']}",
        title="[bold yellow]  INITIATING SCAN  [/bold yellow]",
        border_style="yellow",
    ))

    scan_result = {}
    with Progress(
        SpinnerColumn("dots2"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as prog:
        task = prog.add_task(f"[cyan]{profile_info['label']}…[/cyan]", total=None)
        def _cb(msg): prog.update(task, description=f"[dim]{msg[:55]}[/dim]")
        scan_result = nmap_scanner.run_scan(
            target=target, profile=profile,
            ports=opts.get("ports"), speed=opts.get("speed"),
            scripts=opts.get("scripts"), output_name=opts.get("output"),
            progress_cb=_cb,
        )

    if not scan_result.get("success"):
        assistant.render_error(scan_result.get("error", "Unknown error"))
        if scan_result.get("stderr"):
            console.print(f"  [dim]{scan_result['stderr'][:300]}[/dim]")
        return None

    xml_path = scan_result.get("xml_path")
    if not xml_path:
        assistant.render_warning("Scan completed but no XML output produced.")
        console.print(scan_result.get("stdout", ""))
        return None

    assistant.render_success(f"Scan complete → {xml_path}")

    try:
        parsed = nmap_parser.parse_xml(xml_path)
    except Exception as exc:
        assistant.render_error(f"XML parse failed: {exc}")
        return None

    if not parsed.hosts:
        assistant.render_warning("No hosts detected (target may be down/filtered).")
        return None

    report = analyzer.analyze(parsed)
    assistant.render_report(report, include_llm=opts.get("ai", False))

    # Persist to DB
    try:
        db.save_scan(target, profile, xml_path, scan_result["command"], report)
    except Exception as exc:
        logger.warning("DB save failed: %s", exc)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Auto-recon pipeline
# ─────────────────────────────────────────────────────────────────────────────

def cmd_auto_recon(args: list[str], opts: dict) -> None:
    if not args:
        assistant.render_warning("Usage: auto-recon <target> [--ai]")
        return

    target = args[0]
    console.print()
    console.print(Rule(f"[bold cyan]  AUTO-RECON PIPELINE: {target}  [/bold cyan]", style="cyan"))

    pipeline_steps = [
        ("quick",   "Step 1/4: Quick port discovery"),
        ("full",    "Step 2/4: Full port + service scan"),
        ("vuln",    "Step 3/4: Vulnerability scripts"),
        ("os",      "Step 4/4: OS detection"),
    ]

    final_report: Optional[analyzer.AnalysisReport] = None
    for profile, label in pipeline_steps:
        console.print(f"\n  [bold yellow]{label}[/bold yellow]")
        report = _run_scan_pipeline(target, profile, opts)
        if report and not final_report:
            final_report = report

    # Service graph
    if final_report:
        console.print()
        console.print(Panel(
            analyzer.build_graph(final_report),
            title="[bold white]  Service Graph  [/bold white]",
            border_style="dim",
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Individual handlers
# ─────────────────────────────────────────────────────────────────────────────

def cmd_scan(args: list[str], profile: str) -> None:
    if not args:
        assistant.render_warning(f"Usage: {profile}scan <target> [options]")
        return
    pos, opts = _split_args(args)
    if not pos:
        assistant.render_warning("Provide a target IP/hostname.")
        return
    _run_scan_pipeline(pos[0], profile, opts)


def cmd_analyze(args: list[str]) -> None:
    if not args:
        assistant.render_warning("Usage: analyze <xml_file>")
        return
    xml_path = Path(args[0])
    if not xml_path.exists():
        xml_path = SCANS_DIR / args[0]
    if not xml_path.exists():
        assistant.render_error(f"File not found: {args[0]}")
        return
    try:
        parsed = nmap_parser.parse_xml(xml_path)
    except Exception as exc:
        assistant.render_error(str(exc))
        return
    report = analyzer.analyze(parsed)
    assistant.render_report(report)


def cmd_report(args: list[str]) -> None:
    if not args:
        assistant.render_warning("Usage: report <xml_file> [--format md|html|json|all]")
        return
    pos, opts = _split_args(args)
    if not pos:
        assistant.render_warning("Provide an XML file path.")
        return

    xml_path = Path(pos[0])
    if not xml_path.exists():
        xml_path = SCANS_DIR / pos[0]
    if not xml_path.exists():
        assistant.render_error(f"File not found: {pos[0]}")
        return

    try:
        parsed = nmap_parser.parse_xml(xml_path)
        report = analyzer.analyze(parsed)
    except Exception as exc:
        assistant.render_error(str(exc))
        return

    fmt = opts.get("format", "all")
    if fmt == "all":
        paths = report_generator.generate_all(report)
        for k, p in paths.items():
            assistant.render_success(f"{k.upper()} report → {p}")
    elif fmt == "md":
        p = report_generator.generate_markdown(report)
        assistant.render_success(f"Markdown report → {p}")
    elif fmt == "html":
        p = report_generator.generate_html(report)
        assistant.render_success(f"HTML report → {p}")
    elif fmt == "json":
        p = report_generator.generate_json(report)
        assistant.render_success(f"JSON report → {p}")
    else:
        assistant.render_warning(f"Unknown format '{fmt}'. Use: md, html, json, all")


def cmd_subdomains(args: list[str]) -> None:
    if not args:
        assistant.render_warning("Usage: subdomains <domain>")
        return
    domain = args[0]
    console.print(f"\n  [cyan]Enumerating subdomains for: {domain}[/cyan]\n")
    try:
        from modules.subdomain_enum import enumerate as sub_enum
        with Progress(SpinnerColumn(), TextColumn("[cyan]Querying DNS + CT logs…"),
                      TimeElapsedColumn(), console=console, transient=True) as prog:
            prog.add_task("", total=None)
            result = sub_enum(domain)
    except Exception as exc:
        assistant.render_error(str(exc))
        return

    if not result.subdomains:
        assistant.render_info("No subdomains discovered.")
        return

    table = Table(title=f"Subdomains — {domain}", box=box.SIMPLE, header_style="bold magenta")
    table.add_column("Subdomain",  style="cyan")
    table.add_column("IP Address", style="green")
    table.add_column("Source",     style="dim")
    for s in result.subdomains:
        table.add_row(s.subdomain, s.ip_address or "—", s.source)
    console.print(table)
    console.print(f"  [dim]Found {len(result.subdomains)} subdomains  |  {len(result.unique_ips)} unique IPs[/dim]\n")


def cmd_history(_args: list[str]) -> None:
    try:
        scans = db.list_scans()
    except Exception as exc:
        assistant.render_error(str(exc))
        return
    if not scans:
        assistant.render_info("No scans in history.")
        return
    table = Table(title="Scan History", box=box.SIMPLE, header_style="bold magenta")
    table.add_column("ID",      width=5,  style="dim")
    table.add_column("Target",  style="cyan")
    table.add_column("Profile", style="yellow")
    table.add_column("Hosts",   width=7,  style="green")
    table.add_column("Started", style="dim")
    for row in scans:
        table.add_row(str(row["id"]), row["target"], row["profile"],
                      str(row["host_count"]), row["started_at"])
    console.print(table)


def cmd_scans(_args: list[str]) -> None:
    import datetime
    files = sorted(SCANS_DIR.glob("*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        assistant.render_info(f"No saved scans in {SCANS_DIR}/")
        return
    table = Table(title="Saved XML Scans", box=box.SIMPLE, header_style="bold magenta")
    table.add_column("#",        width=4,  style="dim")
    table.add_column("File",     style="cyan")
    table.add_column("Size",     width=10)
    table.add_column("Modified", style="dim")
    for i, f in enumerate(files, 1):
        st  = f.stat()
        mod = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(str(i), f.name, f"{st.st_size/1024:.1f} KB", mod)
    console.print(table)


def cmd_help(_args: list[str]) -> None:
    console.print(Panel(HELP_TEXT, border_style="cyan", padding=(1, 2)))


def cmd_clear(_args: list[str]) -> None:
    console.clear()
    console.print(BANNER)


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch(line: str) -> bool:
    line = line.strip()
    if not line:
        return True
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        assistant.render_warning(f"Parse error: {exc}")
        return True

    cmd  = tokens[0].lower()
    rest = tokens[1:]
    pos, opts = _split_args(rest)

    if cmd in ("exit", "quit"):
        console.print("\n[dim]Goodbye. Stay ethical.[/dim]\n")
        return False

    elif cmd in CMD_PROFILE:
        profile = CMD_PROFILE[cmd]
        if not pos:
            assistant.render_warning(f"Usage: {cmd} <target> [options]")
        else:
            _run_scan_pipeline(pos[0], profile, opts)

    elif cmd == "auto-recon":
        cmd_auto_recon(pos, opts)

    elif cmd == "analyze":
        cmd_analyze(pos)

    elif cmd == "report":
        cmd_report(rest)

    elif cmd == "subdomains":
        cmd_subdomains(pos)

    elif cmd == "history":
        cmd_history(rest)

    elif cmd == "scans":
        cmd_scans(rest)

    elif cmd in ("help", "?"):
        cmd_help(rest)

    elif cmd == "clear":
        cmd_clear(rest)

    else:
        assistant.render_warning(
            f"Unknown command '{cmd}'. Type [bold]help[/bold] for available commands."
        )

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

def run() -> None:
    console.print(BANNER)
    console.print(Panel(
        f"[bold red]{DISCLAIMER}[/bold red]",
        border_style="red", padding=(0, 2),
    ))
    console.print()
    console.print("  Type [bold cyan]help[/bold cyan] for available commands.\n")

    session: PromptSession = PromptSession(completer=COMPLETER, style=PT_STYLE)

    while True:
        try:
            line = session.prompt(HTML("<prompt>SentinelAI</prompt><b> ❯ </b>"), style=PT_STYLE)
        except KeyboardInterrupt:
            console.print("\n  [dim]Use [bold]exit[/bold] to quit.[/dim]")
            continue
        except EOFError:
            console.print("\n[dim]EOF received. Exiting.[/dim]\n")
            break

        if not _dispatch(line):
            break
