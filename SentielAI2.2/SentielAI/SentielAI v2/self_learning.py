"""
SentinelAI Extension — Self-Learning Intelligence Layer
========================================================
Combines KnowledgeBase + PatternRecognizer to produce improving
recommendations for each new scan.
Hooks into the existing AnalysisReport from analyzer.py.

Usage (add to _run_scan_pipeline in cli.py — DO NOT modify cli.py itself;
       call from your own orchestration layer or cli_ext.py):

    from intelligence.self_learning import SelfLearningLayer
    layer = SelfLearningLayer()
    enhanced_recs = layer.enhance(host_analysis, scoring_result)
    layer.persist(target, host_analysis, scoring_result)
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from intelligence.scan_memory       import ScanMemoryDB
from intelligence.pattern_recognizer import PatternRecognizer
from intelligence.knowledge_base     import KnowledgeBase

if TYPE_CHECKING:
    from analyzer import HostAnalysis
    from scoring.attack_surface_scorer import ScoringResult


class SelfLearningLayer:
    def __init__(self):
        self.mem = ScanMemoryDB()
        self.kb  = KnowledgeBase()
        self.pr  = PatternRecognizer(self.mem)

    # ── public API ─────────────────────────────────────────────────────
    def enhance(self,
                host_analysis: "HostAnalysis",
                scoring_result: "ScoringResult | None" = None) -> list[str]:
        """Return an enhanced, de-duplicated recommendation list."""
        services = [p.display_service for p in host_analysis.host.open_ports]

        # 1. Base recs already in HostAnalysis
        recs: list[str] = list(host_analysis.suggestions)

        # 2. KB-derived techniques for each detected service
        for svc in services:
            for tech in self.kb.techniques(svc):
                recs.append(tech)

        # 3. Pattern-based recs from historical scans
        for p_rec in self.pr.prioritised_recs(services):
            recs.append(p_rec)

        # 4. CVE-specific hints from findings
        import re
        for finding in host_analysis.findings:
            for cve in re.findall(r"CVE-[0-9]{4}-[0-9]+",
                                  finding.title + (finding.detail or "")):
                recs.append(f"Verify and investigate {cve}")

        # Deduplicate preserving order
        seen: set[str] = set()
        unique = []
        for r in recs:
            if r not in seen:
                seen.add(r); unique.append(r)

        return unique[:25]

    def persist(self, target: str,
                host_analysis: "HostAnalysis",
                scoring_result: "ScoringResult | None" = None) -> None:
        """Save scan to memory DB and grow the knowledge base."""
        self.mem.save(target, host_analysis, scoring_result)
        # Grow KB with recommendations generated for each service
        services = [p.display_service for p in host_analysis.host.open_ports]
        recs     = host_analysis.suggestions
        for svc in services:
            self.kb.auto_update(svc, recs)
