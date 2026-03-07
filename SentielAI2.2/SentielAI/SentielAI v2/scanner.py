"""
SentinelAI Scanner Module
==========================
Executes Nmap scans via subprocess, manages output files, and
returns structured result dicts. Reconnaissance only — no exploitation.
"""

import subprocess
import shutil
import logging
import datetime
from pathlib import Path
from typing import Optional, Callable

from config import SCANS_DIR, SCAN_PROFILES, VALID_SPEEDS

logger = logging.getLogger("sentinelai.scanner")


def _nmap_ok() -> bool:
    return shutil.which("nmap") is not None


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_name(s: str) -> str:
    return s.replace("/", "_").replace(":", "_").replace("\\", "_").replace(" ", "_")


def run_scan(
    target: str,
    profile: str = "full",
    ports: Optional[str] = None,
    speed: Optional[str] = None,
    scripts: Optional[str] = None,
    output_name: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> dict:
    """
    Run an Nmap scan and return a result dict.

    Keys: success, xml_path, txt_path, stdout, stderr, command, error
    """
    if not _nmap_ok():
        return _err("nmap not found. Install with: sudo apt install nmap")

    target = target.strip()
    if not target:
        return _err("No target specified.")

    profile = profile.lower()
    if profile not in SCAN_PROFILES:
        return _err(f"Unknown profile '{profile}'. Valid: {', '.join(SCAN_PROFILES)}")

    # ── Build output paths ────────────────────────────────────────────────────
    base_name  = output_name or f"{_safe_name(target)}_{profile}_{_ts()}"
    xml_file   = str(SCANS_DIR / (base_name + ".xml"))
    txt_file   = str(SCANS_DIR / (base_name + ".txt"))

    # ── Build command ─────────────────────────────────────────────────────────
    cmd: list[str] = ["nmap"]
    cmd.extend(SCAN_PROFILES[profile]["args"])

    # Port override — remove any -p in profile args first
    if ports:
        cmd = [a for a in cmd if a != "-p-" and not a.startswith("-p")]
        cmd += ["-p", ports]

    # Timing override
    if speed:
        speed = speed.upper()
        if speed not in VALID_SPEEDS:
            return _err(f"Invalid speed '{speed}'. Valid: {', '.join(sorted(VALID_SPEEDS))}")
        cmd = [a for a in cmd if not a.startswith("-T")]
        cmd.append(f"-{speed}")

    # Extra NSE scripts (additive)
    if scripts:
        cmd += ["--script", scripts]

    # Arbitrary extra args
    if extra_args:
        cmd.extend(extra_args)

    # Output formats
    cmd += ["-oX", xml_file, "-oN", txt_file, target]

    logger.info("Executing: %s", " ".join(cmd))
    if progress_cb:
        progress_cb(f"cmd: {' '.join(cmd)}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return _err("Scan timed out after 15 minutes.")
    except Exception as exc:
        return _err(str(exc))

    xml_path = Path(xml_file) if Path(xml_file).exists() else None
    txt_path = Path(txt_file) if Path(txt_file).exists() else None

    return {
        "success":  proc.returncode == 0,
        "xml_path": xml_path,
        "txt_path": txt_path,
        "stdout":   proc.stdout,
        "stderr":   proc.stderr,
        "command":  " ".join(cmd),
        "profile":  profile,
        "target":   target,
        "error":    proc.stderr if proc.returncode != 0 else None,
    }


def _err(msg: str) -> dict:
    return {
        "success": False, "xml_path": None, "txt_path": None,
        "stdout": "", "stderr": "", "command": "", "profile": "",
        "target": "", "error": msg,
    }


# ── Convenience wrappers ──────────────────────────────────────────────────────
def quickscan(target, **kw):   return run_scan(target, "quick",   **kw)
def fullscan(target, **kw):    return run_scan(target, "full",    **kw)
def osscan(target, **kw):      return run_scan(target, "os",      **kw)
def vulnscan(target, **kw):    return run_scan(target, "vuln",    **kw)
def stealthscan(target, **kw): return run_scan(target, "stealth", **kw)
def portscan(target, **kw):    return run_scan(target, "ports",   **kw)
def webscan(target, **kw):     return run_scan(target, "web",     **kw)
def smbscan(target, **kw):     return run_scan(target, "smb",     **kw)
