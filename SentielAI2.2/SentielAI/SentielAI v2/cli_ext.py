"""
SentinelAI Extension — CLI Extension Layer
===========================================
Adds commands and post-scan hooks to the existing SentinelAI CLI
WITHOUT modifying cli.py, scanner.py, or any other existing module.

Two integration modes:

MODE A — call from main.py (preferred, clean):
    Patch after importing cli:
        import cli_ext
        cli_ext.patch_cli()
    Then call cli.run() as normal.

MODE B — standalone entry point:
    python cli_ext.py score scans/result.xml
    python cli_ext.py dashboard
    python cli_ext.py autorecon 192.168.1.10

The extension hooks post-scan scoring + intelligence into any scan
result produced by the existing pipeline by wrapping _run_scan_pipeline.
"""
from __future__ import annotations
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel   import Panel
from rich.rule    import Rule
from rich.table   import Table
from rich         import box

console = Console()


# ── lazy-import helpers (keep imports optional / offline-safe) ────────────────
def _scorer():
    from scoring.attack_surface_scorer import AttackSurfaceScorer
    return AttackSurfaceScorer()

def _layer():
    from intelligence.self_learning import SelfLearningLayer
    return SelfLearningLayer()

def _orch():
    from tool_orchestrator import ToolOrchestrator
    return ToolOrchestrator()


# ── post-scan hook ─────────────────────────────────────────────────────────────
def run_post_scan_hooks(target: str, analysis_report) -> None:
    """
    Call this after every scan to:
      1. Compute enhanced attack surface score
      2. Generate self-learning recommendations
      3. Persist to intelligence DB
      4. Print enhanced output
    """
    from assistant import render_info
    scorer = _scorer()
    layer  = _layer()

    for ha in analysis_report.host_analyses:
        score_result = scorer.score_host(ha)
        enhanced     = layer.enhance(ha, score_result)

        # Display
        console.print(Panel(
            score_result.rich_panel(),
            title="[bold cyan]  ATTACK SURFACE SCORE  [/bold cyan]",
            border_style="cyan", padding=(0, 1),
        ))

        if enhanced:
            console.print(Panel(
                "\n".join(f"  [green]•[/green] {r}" for r in enhanced[:12]),
                title="[bold green]  INTELLIGENCE-ENHANCED RECOMMENDATIONS  [/bold green]",
                border_style="green", padding=(0, 1),
            ))

        # Persist
        layer.persist(target, ha, score_result)
        render_info(f"Intelligence saved for {target}")


# ── patch cli._run_scan_pipeline ──────────────────────────────────────────────
def patch_cli() -> None:
    """
    Wrap cli._run_scan_pipeline to automatically call run_post_scan_hooks
    after every successful scan.  Call once from main.py.
    """
    import cli as _cli

    _original = _cli._run_scan_pipeline

    def _patched(target, profile, opts):
        report = _original(target, profile, opts)
        if report is not None:
            try:
                run_post_scan_hooks(target, report)
            except Exception as exc:
                console.print(f"  [dim yellow][ext] post-scan hooks error: {exc}[/dim yellow]")
        return report

    _cli._run_scan_pipeline = _patched
    console.print("  [dim cyan][ext] Intelligence hooks active[/dim cyan]")


# ── standalone commands ────────────────────────────────────────────────────────
def cmd_score(xml_path_str: str) -> None:
    import parser as nmap_parser
    import analyzer

    xml = Path(xml_path_str)
    if not xml.exists():
        from config import SCANS_DIR
        xml = SCANS_DIR / xml_path_str
    if not xml.exists():
        console.print(f"[red]File not found: {xml_path_str}[/red]"); return

    parsed = nmap_parser.parse_xml(xml)
    report = analyzer.analyze(parsed)
    scorer = _scorer()

    for ha in report.host_analyses:
        result = scorer.score_host(ha)
        console.print(result)


def cmd_autorecon_ext(target: str, use_ai: bool = False,
                      use_tools: bool = False) -> None:
    """Extended auto-recon: scoring + intelligence + optional tool orchestration."""
    import parser as nmap_parser
    import analyzer
    import scanner as nmap_scanner
    from config import SCAN_PROFILES

    console.print()
    console.print(Rule(f"[bold cyan]  EXT AUTO-RECON: {target}  [/bold cyan]", style="cyan"))

    steps = [("quick","Quick port discovery"),("full","Service detection"),
             ("vuln","Vulnerability scripts"),("os","OS detection")]

    final_report = None
    for profile, label in steps:
        console.print(f"\n  [bold yellow][+] {label}[/bold yellow]")
        result = nmap_scanner.run_scan(target=target, profile=profile)
        if not result.get("success") or not result.get("xml_path"):
            console.print(f"  [dim red]  Scan step failed: {result.get('error','')}[/dim red]")
            continue
        try:
            parsed = nmap_parser.parse_xml(result["xml_path"])
            report = analyzer.analyze(parsed)
            if not final_report and report.host_analyses:
                final_report = report
        except Exception as exc:
            console.print(f"  [dim red]Parse error: {exc}[/dim red]")

    if final_report:
        run_post_scan_hooks(target, final_report)

    if use_tools and final_report:
        orch = _orch()
        console.print(Rule("[bold magenta]  TOOL ORCHESTRATION  [/bold magenta]", style="magenta"))
        for ha in final_report.host_analyses:
            results = orch.auto_run(ha)
            for tr in results:
                status = "[green]OK[/green]" if tr.success else "[red]ERR[/red]"
                console.print(f"  [{status}] {tr.tool} → {tr.short_summary}")


def cmd_dashboard() -> None:
    """Launch the SentinelAI web dashboard."""
    try:
        from dashboard.app import create_app
        app = create_app()
        console.print(Panel(
            "[cyan]Dashboard running at http://127.0.0.1:5000[/cyan]\n"
            "[dim]Press Ctrl+C to stop[/dim]",
            title="[bold cyan]  SENTINEL AI DASHBOARD  [/bold cyan]",
            border_style="cyan",
        ))
        app.run(host="0.0.0.0", port=5000, debug=False)
    except ImportError as exc:
        console.print(f"[red]Dashboard unavailable: {exc}[/red]")
        console.print("[dim]Install: pip install flask[/dim]")


def cmd_intel() -> None:
    """Show intelligence patterns from scan memory."""
    from intelligence.scan_memory       import ScanMemoryDB
    from intelligence.pattern_recognizer import PatternRecognizer

    mem     = ScanMemoryDB()
    pr      = PatternRecognizer(mem)
    insights = pr.analyze()

    console.print(Rule("[bold cyan]  INTELLIGENCE PATTERNS  [/bold cyan]", style="cyan"))

    if insights["frequent_services"]:
        t = Table("Service", "Count", title="Frequent Services",
                  box=box.SIMPLE, header_style="bold magenta")
        for row in insights["frequent_services"][:10]:
            t.add_row(row["service"], str(row["count"]))
        console.print(t)

    if insights["frequent_cves"]:
        t = Table("CVE", "Count", title="Frequent CVEs",
                  box=box.SIMPLE, header_style="bold magenta")
        for row in insights["frequent_cves"][:10]:
            t.add_row(row["cve"], str(row["count"]))
        console.print(t)

    if insights["top_enum_hints"]:
        console.print("\n[bold]Top Enumeration Hints[/bold]")
        for h in insights["top_enum_hints"][:8]:
            console.print(f"  [green]→[/green] {h}")


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="sentinelai-ext",
                                 description="SentinelAI Intelligence Extension CLI")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("score",     help="Score an existing XML scan file")
    sp.add_argument("xml")

    ar = sub.add_parser("autorecon", help="Extended auto-recon with scoring + intel")
    ar.add_argument("target")
    ar.add_argument("--tools", action="store_true", help="Run tool orchestration")
    ar.add_argument("--ai",    action="store_true", help="Include LLM analysis")

    sub.add_parser("dashboard", help="Launch web dashboard")
    sub.add_parser("intel",     help="Show intelligence pattern report")

    args = ap.parse_args()
    dispatch = {
        "score":     lambda: cmd_score(args.xml),
        "autorecon": lambda: cmd_autorecon_ext(args.target,
                                               use_ai=getattr(args,"ai",False),
                                               use_tools=getattr(args,"tools",False)),
        "dashboard": cmd_dashboard,
        "intel":     cmd_intel,
    }
    fn = dispatch.get(args.cmd)
    if fn:
        fn()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
