"""
SentinelAI Knowledge Base
==========================
Service → attack technique map.
Seeded from config.SERVICE_KB; grows via scan history stored at database/knowledge_base.json.
"""
from __future__ import annotations
import json
from pathlib import Path

from config import SERVICE_KB

_KB_PATH = Path(__file__).parent.parent / "database" / "knowledge_base.json"


def _seed_from_config() -> dict[str, list[str]]:
    """Build initial technique list from config.SERVICE_KB suggestions."""
    seed: dict[str, list[str]] = {}
    for svc, data in SERVICE_KB.items():
        seed[svc] = list(data.get("suggestions", []))
    return seed


class KnowledgeBase:
    def __init__(self, path: Path = _KB_PATH):
        self._path = path
        self._kb: dict[str, list[str]] = _seed_from_config()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                stored = json.loads(self._path.read_text())
                for svc, techs in stored.items():
                    if svc in self._kb:
                        self._kb[svc] = list(dict.fromkeys(self._kb[svc] + techs))
                    else:
                        self._kb[svc] = techs
            except Exception:
                pass

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._kb, indent=2))

    def techniques(self, service: str) -> list[str]:
        svc = service.lower().strip()
        for key in self._kb:
            if key in svc or svc in key:
                return list(self._kb[key])
        return []

    def auto_update(self, service: str, new_techniques: list[str]) -> None:
        svc = service.lower().strip()
        existing = self._kb.get(svc, [])
        merged = list(dict.fromkeys(existing + [t for t in new_techniques if t]))
        if merged != existing:
            self._kb[svc] = merged
            self._save()

    def all_entries(self) -> dict[str, list[str]]:
        return dict(self._kb)
