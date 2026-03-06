"""
SentinelAI — Entry Point
=========================
Initialises logging, then hands control to the interactive CLI.

Usage
-----
    python main.py                   # start interactive session
    python main.py --log-level DEBUG # verbose logging
    python main.py --version         # print version and exit
"""

import argparse
import logging
import sys
from pathlib import Path

# ── Ensure the project root is on sys.path when run directly ─────────────────
sys.path.insert(0, str(Path(__file__).parent))

from config import TOOL_NAME, TOOL_VERSION, LOGS_DIR


def _setup_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    log_file = LOGS_DIR / "sentinelai.log"

    handlers: list[logging.Handler] = [
        logging.FileHandler(log_file, encoding="utf-8"),
    ]

    # Only add a StreamHandler for DEBUG so Rich output isn't polluted
    if numeric_level == logging.DEBUG:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )
    logging.getLogger("sentinelai").setLevel(numeric_level)


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="sentinelai",
        description=f"{TOOL_NAME} — Recon Assistant for Authorised Lab Environments",
    )
    ap.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    ap.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    args = ap.parse_args()

    _setup_logging(args.log_level)
    logger = logging.getLogger("sentinelai.main")
    logger.info("Starting %s v%s", TOOL_NAME, TOOL_VERSION)

    # Late import so Rich banner appears only after logging is configured
    from cli import run
    run()


if __name__ == "__main__":
    main()
