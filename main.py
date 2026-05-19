"""
SentinelAI v2 — Entry Point
=============================
Initialises logging and database, then launches the interactive CLI.

Usage
-----
  python main.py                    # interactive mode
  python main.py --log-level DEBUG  # verbose
  python main.py --version
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import TOOL_NAME, TOOL_VERSION, LOGS_DIR


def _setup_logging(level: str) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    log_file = LOGS_DIR / "sentinelai.log"
    handlers: list[logging.Handler] = [
        logging.FileHandler(log_file, encoding="utf-8"),
    ]
    if numeric == logging.DEBUG:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="sentinelai",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Advanced Recon Assistant",
    )
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    ap.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = ap.parse_args()

    _setup_logging(args.log_level)
    logger = logging.getLogger("sentinelai.main")
    logger.info("Starting %s v%s", TOOL_NAME, TOOL_VERSION)

    # Init DB (creates tables if missing)
    from database.db import init_db
    try:
        init_db()
    except Exception as exc:
        logger.warning("DB init failed: %s", exc)

    from cli import run
    run()


if __name__ == "__main__":
    main()
