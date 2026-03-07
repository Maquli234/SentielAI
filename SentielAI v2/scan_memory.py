"""
SentinelAI Extension — Scan Memory Database
============================================
Adds a second SQLite database (intelligence.db) that stores historical
intelligence data for the self-learning layer.

DOES NOT modify database/db.py.

Usage:
    from intelligence.scan_memory import ScanMemoryDB
    mem = ScanMemoryDB()
    mem.save(target, host_analysis, risk_result)
"""
from __future__ import annotations
import json, sqlite3, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analyzer import HostAnalysis
    from scoring.attack_surface_scorer import ScoringResult

# Place alongside existing database/ directory
_DB_DIR  = Path(__file__).parent.parent / "database"
_DB_DIR.mkdir(parents=True, exist_ok=True)
INTEL_DB = _DB_DIR / "intelligence.db"

_DDL = """
CREATE TABLE IF NOT EXISTS intel_scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT    NOT NULL,
    scanned_at   TEXT    NOT NULL,
    open_ports   TEXT,    -- JSON [int]
    services     TEXT,    -- JSON [str]
    versions     TEXT,    -- JSON [str]
    cves         TEXT,    -- JSON [str]
    enum_recs    TEXT,    -- JSON [str]
    attack_vecs  TEXT,    -- JSON [str]
    risk_score   REAL     DEFAULT 0,
    severity     TEXT     DEFAULT 'INFO'
);
CREATE INDEX IF NOT EXISTS idx_intel_target ON intel_scans(target);
CREATE INDEX IF NOT EXISTS idx_intel_time   ON intel_scans(scanned_at);
"""

class ScanMemoryDB:
    def __init__(self, db_path: Path = INTEL_DB):
        self._path = db_path
        conn = self._connect()
        conn.executescript(_DDL)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        return conn

    # ── write ─────────────────────────────────────────────────────────
    def save(self,
             target: str,
             host_analysis: "HostAnalysis",
             scoring_result: "ScoringResult | None" = None) -> int:
        host     = host_analysis.host
        ports    = [p.port for p in host.open_ports]
        services = [p.display_service for p in host.open_ports]
        versions = [p.version_string   for p in host.open_ports if p.version_string]
        cves: list[str] = []
        for f in host_analysis.findings:
            import re
            cves.extend(re.findall(r"CVE-[0-9]{4}-[0-9]+", f.title + (f.detail or "")))
        cves = list(dict.fromkeys(cves))

        enum_recs   = host_analysis.suggestions[:20]
        attack_vecs = host_analysis.attack_vectors[:20]
        risk_score  = scoring_result.risk_score if scoring_result else (
            host_analysis.risk_score.score if host_analysis.risk_score else 0.0)
        severity    = scoring_result.severity if scoring_result else (
            host_analysis.risk_score.label  if host_analysis.risk_score else "INFO")

        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO intel_scans
                  (target, scanned_at, open_ports, services, versions, cves,
                   enum_recs, attack_vecs, risk_score, severity)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                target,
                datetime.datetime.now().isoformat(timespec="seconds"),
                json.dumps(ports),
                json.dumps(services),
                json.dumps(versions),
                json.dumps(cves),
                json.dumps(enum_recs),
                json.dumps(attack_vecs),
                risk_score,
                severity,
            ))
            return cur.lastrowid

    # ── read ──────────────────────────────────────────────────────────
    def history(self, target: str | None = None,
                limit: int = 200) -> list[dict]:
        q    = "SELECT * FROM intel_scans"
        args: list[Any] = []
        if target:
            q += " WHERE target = ?"; args.append(target)
        q += " ORDER BY scanned_at DESC LIMIT ?"; args.append(limit)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(q, args).fetchall()]

    def service_frequency(self, top: int = 20) -> list[tuple[str, int]]:
        freq: dict[str, int] = {}
        with self._connect() as conn:
            for r in conn.execute("SELECT services FROM intel_scans").fetchall():
                for s in json.loads(r["services"] or "[]"):
                    freq[s.lower()] = freq.get(s.lower(), 0) + 1
        return sorted(freq.items(), key=lambda x: -x[1])[:top]

    def cve_frequency(self, top: int = 20) -> list[tuple[str, int]]:
        freq: dict[str, int] = {}
        with self._connect() as conn:
            for r in conn.execute("SELECT cves FROM intel_scans").fetchall():
                for c in json.loads(r["cves"] or "[]"):
                    freq[c] = freq.get(c, 0) + 1
        return sorted(freq.items(), key=lambda x: -x[1])[:top]
