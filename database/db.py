"""
SentinelAI Database Module
============================
Stores scan history, host summaries, and vulnerability intelligence
in a local SQLite database (targets.db).

Schema
------
scans      – one row per scan run
hosts      – one row per host per scan
port_info  – one row per open port per host
findings   – vulnerability/misconfiguration findings
"""

import sqlite3
import json
import logging
import datetime
from pathlib import Path
from typing import Optional

from config import DB_PATH

logger = logging.getLogger("sentinelai.db")

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    profile     TEXT    NOT NULL,
    xml_path    TEXT,
    command     TEXT,
    started_at  TEXT    NOT NULL,
    duration    REAL,
    host_count  INTEGER DEFAULT 0,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id),
    address     TEXT    NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    os_accuracy INTEGER,
    risk_score  REAL,
    risk_label  TEXT,
    open_ports  TEXT,   -- JSON array of port numbers
    mac_address TEXT,
    state       TEXT
);

CREATE TABLE IF NOT EXISTS port_info (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    port        INTEGER NOT NULL,
    protocol    TEXT,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    extra_info  TEXT,
    state       TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    severity    TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    detail      TEXT,
    port        INTEGER,
    created_at  TEXT    NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they do not exist."""
    with _connect() as conn:
        conn.executescript(_CREATE_SQL)
    logger.debug("Database initialised at %s", DB_PATH)


def save_scan(
    target: str,
    profile: str,
    xml_path: Optional[str],
    command: str,
    analysis_report,   # AnalysisReport from analyzer
) -> int:
    """Persist a completed scan and return the scan_id."""
    now = datetime.datetime.now().isoformat(timespec="seconds")

    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, profile, xml_path, command, started_at, host_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target, profile, str(xml_path) if xml_path else None,
             command, now, len(analysis_report.host_analyses)),
        )
        scan_id = cur.lastrowid

        for ha in analysis_report.host_analyses:
            host = ha.host
            os_guess    = host.best_os.name     if host.best_os else ""
            os_accuracy = host.best_os.accuracy if host.best_os else 0
            open_ports  = json.dumps([p.port for p in host.open_ports])
            risk_score  = ha.risk_score.score if ha.risk_score else 0
            risk_label  = ha.risk_score.label if ha.risk_score else ""

            hcur = conn.execute(
                "INSERT INTO hosts (scan_id, address, hostname, os_guess, os_accuracy, "
                "risk_score, risk_label, open_ports, mac_address, state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, host.address, host.hostname, os_guess, os_accuracy,
                 risk_score, risk_label, open_ports, host.mac_address, host.state),
            )
            host_id = hcur.lastrowid

            for p in host.open_ports:
                conn.execute(
                    "INSERT INTO port_info (host_id, port, protocol, service, product, "
                    "version, extra_info, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (host_id, p.port, p.protocol, p.service, p.product,
                     p.version, p.extra_info, p.state),
                )

            for f in ha.findings:
                conn.execute(
                    "INSERT INTO findings (host_id, severity, title, detail, port, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (host_id, f.severity, f.title, f.detail, f.port, now),
                )

    logger.info("Saved scan_id=%d for target=%s", scan_id, target)
    return scan_id


def list_scans(limit: int = 20) -> list[sqlite3.Row]:
    """Return the most recent scans."""
    with _connect() as conn:
        return conn.execute(
            "SELECT id, target, profile, started_at, host_count "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def get_scan(scan_id: int) -> Optional[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()


def get_hosts_for_scan(scan_id: int) -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)
        ).fetchall()


def get_findings_for_host(host_id: int) -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM findings WHERE host_id = ? ORDER BY "
            "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END",
            (host_id,),
        ).fetchall()
