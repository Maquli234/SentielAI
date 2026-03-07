"""
SentinelAI Extension — Web Recon Dashboard (Flask)
===================================================
Read-only: reads database/targets.db (existing) and
database/intelligence.db (extension). Does NOT modify any existing module.

Run standalone:  python dashboard/app.py
Via cli_ext.py:  python cli_ext.py dashboard
"""
from __future__ import annotations
import json, sqlite3
from pathlib import Path
from flask import Flask, jsonify, render_template_string  # type: ignore

_DB_DIR = Path(__file__).parent.parent.parent / "database"

def _conn(name: str):
    p = _DB_DIR / name
    if not p.exists(): return None
    c = sqlite3.connect(str(p)); c.row_factory = sqlite3.Row; return c

def _q(c, sql, args=()):
    if c is None: return []
    try: return [dict(r) for r in c.execute(sql, args).fetchall()]
    except Exception: return []

def create_app() -> Flask:
    app = Flask(__name__)
    _HTML = open(Path(__file__).parent / "templates" / "dashboard.html").read()

    @app.route("/")
    def index():
        return render_template_string(_HTML)

    @app.route("/api/scans")
    def api_scans():
        c = _conn("targets.db")
        r = _q(c, "SELECT id,target,profile,started_at,host_count FROM scans ORDER BY id DESC LIMIT 100")
        if c: c.close(); return jsonify(r)

    @app.route("/api/hosts")
    def api_hosts():
        c = _conn("targets.db")
        r = _q(c, "SELECT id,scan_id,address,hostname,os_guess,risk_score,risk_label,open_ports FROM hosts ORDER BY risk_score DESC LIMIT 200")
        if c: c.close(); return jsonify(r)

    @app.route("/api/findings")
    def api_findings():
        c = _conn("targets.db")
        r = _q(c, """SELECT f.severity,f.title,f.port,h.address,h.risk_label
            FROM findings f JOIN hosts h ON f.host_id=h.id
            ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                     WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END LIMIT 200""")
        if c: c.close(); return jsonify(r)

    @app.route("/api/intel/history")
    def api_intel_history():
        c = _conn("intelligence.db")
        r = _q(c, "SELECT * FROM intel_scans ORDER BY scanned_at DESC LIMIT 200")
        if c: c.close(); return jsonify(r)

    @app.route("/api/intel/services")
    def api_intel_services():
        c = _conn("intelligence.db")
        if not c: return jsonify([])
        freq: dict[str,int] = {}
        for row in _q(c, "SELECT services FROM intel_scans"):
            for s in json.loads(row.get("services") or "[]"):
                freq[s.lower()] = freq.get(s.lower(),0)+1
        c.close(); return jsonify(sorted(freq.items(), key=lambda x:-x[1])[:20])

    @app.route("/api/intel/cves")
    def api_intel_cves():
        c = _conn("intelligence.db")
        if not c: return jsonify([])
        freq: dict[str,int] = {}
        for row in _q(c, "SELECT cves FROM intel_scans"):
            for cve in json.loads(row.get("cves") or "[]"):
                freq[cve] = freq.get(cve,0)+1
        c.close(); return jsonify(sorted(freq.items(), key=lambda x:-x[1])[:20])

    return app

if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=False)
