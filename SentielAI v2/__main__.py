"""
Entry point for `sentinelai` console script and `python -m sentinelai`.
Mirrors the logic in main.py so the package is launchable both ways.
"""
import argparse
import logging
import sys
from pathlib import Path

# Allow running from the project root (src layout fallback)
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

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

    from database.db import init_db
    try:
        init_db()
    except Exception as exc:
        logger.warning("DB init failed: %s", exc)

    from cli import run
    run()


if __name__ == "__main__":
    main()
