"""
SentinelAI Extension — Pattern Recognizer
==========================================
Mines ScanMemoryDB to surface repeating patterns and
return prioritised recommendations for new scans.
"""
from __future__ import annotations
import json
from collections import Counter
from typing import Any

class PatternRecognizer:
    MIN_COUNT = 2   # minimum occurrences to be significant

    def __init__(self, mem_db):
        self.db = mem_db

    def analyze(self) -> dict[str, Any]:
        history = self.db.history(limit=500)
        return {
            "frequent_services":  self._freq_services(history),
            "frequent_cves":      self._freq_cves(history),
            "service_techniques": self._service_technique_map(history),
            "high_risk_targets":  self._high_risk(history),
            "top_enum_hints":     self._top_hints(history),
        }

    def prioritised_recs(self, current_services: list[str]) -> list[str]:
        """Return ordered recs tuned for current_services using historical patterns."""
        insights = self.analyze()
        recs: list[str] = []
        svc_low = [s.lower() for s in current_services]

        for svc, counter in insights["service_techniques"].items():
            if any(svc in s for s in svc_low):
                for technique, count in counter.most_common(4):
                    recs.append(f"[{count}x seen] {technique}  (re: {svc})")

        for hint in insights["top_enum_hints"]:
            if hint not in recs:
                recs.append(hint)

        return recs[:15]

    # ── helpers ───────────────────────────────────────────────────────
    def _freq_services(self, history):
        c: Counter = Counter()
        for r in history:
            for s in json.loads(r.get("services") or "[]"):
                c[s.lower()] += 1
        return [{"service": s, "count": n} for s, n in c.most_common(20) if n >= self.MIN_COUNT]

    def _freq_cves(self, history):
        c: Counter = Counter()
        for r in history:
            for cve in json.loads(r.get("cves") or "[]"):
                c[cve] += 1
        return [{"cve": cve, "count": n} for cve, n in c.most_common(20) if n >= self.MIN_COUNT]

    def _service_technique_map(self, history) -> dict[str, Counter]:
        mapping: dict[str, Counter] = {}
        for r in history:
            svcs = [s.lower() for s in json.loads(r.get("services") or "[]")]
            recs = json.loads(r.get("enum_recs") or "[]")
            cves = json.loads(r.get("cves") or "[]")
            for svc in svcs:
                mapping.setdefault(svc, Counter())
                for rec in recs: mapping[svc][rec] += 1
                for cve in cves: mapping[svc][f"Check {cve}"] += 1
        return {k: v for k, v in mapping.items() if sum(v.values()) >= self.MIN_COUNT}

    def _high_risk(self, history):
        targets: dict[str, list[float]] = {}
        for r in history:
            t = r.get("target", "")
            targets.setdefault(t, []).append(r.get("risk_score", 0.0))
        result = [{"target": t, "avg_risk": round(sum(s)/len(s), 2), "scans": len(s)}
                  for t, s in targets.items() if sum(s)/len(s) >= 5.0]
        return sorted(result, key=lambda x: -x["avg_risk"])[:10]

    def _top_hints(self, history):
        c: Counter = Counter()
        for r in history:
            for h in json.loads(r.get("enum_recs") or "[]"):
                c[h] += 1
        return [h for h, n in c.most_common(15) if n >= self.MIN_COUNT]
