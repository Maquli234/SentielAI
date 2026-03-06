"""
SentinelAI Scanner Module
==========================
Executes Nmap scans via subprocess, stores XML output, and
returns the path to the result file.

Design principles
-----------------
• NO automatic exploitation — scanning and reconnaissance only.
• All results are saved as XML for offline parsing.
• Users can override ports, timing, and extra scripts via kwargs.
"""

import subprocess
import shutil
import logging
import datetime
from pathlib import Path
from typing import Optional

from config import SCANS_DIR, SCAN_PROFILES, VALID_SPEEDS

logger = logging.getLogger("sentinelai.scanner")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _nmap_available() -> bool:
    """Return True if nmap is on the PATH."""
    return shutil.which("nmap") is not None


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _output_path(target: str, profile: str) -> Path:
    """Build a unique output file path inside SCANS_DIR."""
    # Sanitise target for use as a filename component
    safe_target = target.replace("/", "_").replace(":", "_").replace("\\", "_")
    filename = f"{safe_target}_{profile}_{_timestamp()}"
    return SCANS_DIR / filename


# ─────────────────────────────────────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(
    target: str,
    profile: str = "quick",
    ports: Optional[str] = None,
    speed: Optional[str] = None,
    scripts: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    progress_callback=None,
) -> dict:
    """
    Execute an Nmap scan and return a result dict.

    Parameters
    ----------
    target          : IP address or hostname to scan
    profile         : one of the keys in SCAN_PROFILES
    ports           : port range override, e.g. "1-1000" or "22,80,443"
    speed           : nmap timing template, e.g. "T3"
    scripts         : comma-separated NSE scripts, e.g. "http-title,ftp-anon"
    extra_args      : arbitrary extra nmap arguments (list of strings)
    progress_callback: optional callable(message: str) for UI updates

    Returns
    -------
    dict with keys:
        success   – bool
        xml_path  – Path to XML output file (or None on failure)
        stdout    – raw stdout text
        stderr    – raw stderr text
        command   – the full nmap command that was run
        error     – error message if success is False
    """

    # ── Pre-flight checks ─────────────────────────────────────────────────────
    if not _nmap_available():
        return {
            "success": False,
            "xml_path": None,
            "stdout": "",
            "stderr": "",
            "command": "",
            "error": "nmap not found. Install it with: sudo apt install nmap",
        }

    if not target or not target.strip():
        return {
            "success": False,
            "xml_path": None,
            "stdout": "",
            "stderr": "",
            "command": "",
            "error": "No target specified.",
        }

    profile = profile.lower()
    if profile not in SCAN_PROFILES:
        return {
            "success": False,
            "xml_path": None,
            "stdout": "",
            "stderr": "",
            "command": "",
            "error": f"Unknown scan profile '{profile}'. Valid: {', '.join(SCAN_PROFILES)}",
        }

    # ── Build command ─────────────────────────────────────────────────────────
    out_path = _output_path(target, profile)
    xml_file = str(out_path) + ".xml"

    cmd: list[str] = ["nmap"]

    # Profile-specific flags
    cmd.extend(SCAN_PROFILES[profile]["args"])

    # Port override
    if ports:
        # Replace any existing -p flag from the profile
        cmd = [a for a in cmd if not a.startswith("-p")]
        cmd.extend(["-p", ports])

    # Speed / timing override (must be a valid nmap template)
    if speed:
        speed = speed.upper()
        if speed not in VALID_SPEEDS:
            return {
                "success": False,
                "xml_path": None,
                "stdout": "",
                "stderr": "",
                "command": "",
                "error": f"Invalid speed '{speed}'. Valid: {', '.join(sorted(VALID_SPEEDS))}",
            }
        # Remove any existing timing flag from profile args
        cmd = [a for a in cmd if not a.startswith("-T")]
        cmd.extend([f"-{speed}"])

    # Additional NSE scripts
    if scripts:
        cmd.extend(["--script", scripts])

    # Extra arbitrary arguments
    if extra_args:
        cmd.extend(extra_args)

    # XML output (always saved; normal output also shown)
    cmd.extend([
        "-oX", xml_file,   # Save XML to file
        "-oN", str(out_path) + ".txt",  # Also save normal (human-readable) output
        target,
    ])

    logger.info("Running: %s", " ".join(cmd))
    if progress_callback:
        progress_callback(f"Executing: {' '.join(cmd)}")

    # ── Execute ───────────────────────────────────────────────────────────────
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,   # 10-minute hard cap
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "xml_path": None,
            "stdout": "",
            "stderr": "",
            "command": " ".join(cmd),
            "error": "Scan timed out after 600 seconds.",
        }
    except Exception as exc:
        return {
            "success": False,
            "xml_path": None,
            "stdout": "",
            "stderr": "",
            "command": " ".join(cmd),
            "error": str(exc),
        }

    xml_path = Path(xml_file) if Path(xml_file).exists() else None

    return {
        "success": result.returncode == 0,
        "xml_path": xml_path,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": " ".join(cmd),
        "error": result.stderr if result.returncode != 0 else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrappers (map to named CLI commands)
# ─────────────────────────────────────────────────────────────────────────────

def quickscan(target: str, **kwargs) -> dict:
    return run_scan(target, profile="quick", **kwargs)


def fullscan(target: str, **kwargs) -> dict:
    return run_scan(target, profile="full", **kwargs)


def osscan(target: str, **kwargs) -> dict:
    return run_scan(target, profile="os", **kwargs)


def vulnscan(target: str, **kwargs) -> dict:
    return run_scan(target, profile="vuln", **kwargs)


def stealthscan(target: str, **kwargs) -> dict:
    return run_scan(target, profile="stealth", **kwargs)


def portscan(target: str, **kwargs) -> dict:
    return run_scan(target, profile="ports", **kwargs)
