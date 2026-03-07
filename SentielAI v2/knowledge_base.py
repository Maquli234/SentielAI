"""
SentinelAI Extension — Intelligence Knowledge Base
===================================================
Local service → attack technique map.
Seeded from config.SERVICE_KB and grows via scan history.
Stored at database/knowledge_base.json.
"""
from __future__ import annotations
import json
from pathlib import Path

_KB_PATH = Path(__file__).parent.parent / "database" / "knowledge_base.json"

# Seed from SERVICE_KB in config.py — keys must match service name substrings
_SEED: dict[str, list[str]] = {
    "ftp":           ["anonymous login check", "brute force FTP credentials",
                      "check version CVEs", "directory listing via ftp-ls NSE"],
    "ssh":           ["audit SSH algorithms", "brute force SSH credentials",
                      "check username enumeration CVE-2018-15473", "banner grab"],
    "http":          ["directory brute force (gobuster)", "web vulnerability scan (nikto)",
                      "CMS fingerprinting (whatweb)", "endpoint fuzzing (ffuf)"],
    "https":         ["TLS audit (sslscan/testssl.sh)", "directory brute force",
                      "certificate inspection", "web vulnerability scan"],
    "smb":           ["SMB share enumeration", "null session check",
                      "user enumeration via enum4linux", "check EternalBlue MS17-010",
                      "NTLM relay assessment"],
    "rdp":           ["check BlueKeep CVE-2019-0708", "credential brute force",
                      "NLA configuration check"],
    "vnc":           ["no-auth check", "credential brute force", "banner grab"],
    "redis":         ["check unauthenticated access", "CONFIG GET dump",
                      "test RCE via CONFIG SET"],
    "mongodb":       ["open database exposure", "list databases without auth",
                      "data exfiltration assessment"],
    "mysql":         ["default credentials (root/blank)", "brute force MySQL",
                      "NSE mysql-databases,mysql-info"],
    "postgres":      ["default credentials (postgres/blank)", "brute force",
                      "check COPY TO/FROM exploitation"],
    "mssql":         ["xp_cmdshell check", "SA account brute force",
                      "linked servers enumeration"],
    "elasticsearch": ["open REST API check", "list indices (/_cat/indices)",
                      "data exfiltration"],
    "ldap":          ["anonymous bind check", "user enumeration via ldapsearch",
                      "brute force credentials"],
    "snmp":          ["community string brute force (onesixtyone)",
                      "snmpwalk for system info", "check write access"],
    "nfs":           ["showmount -e", "check no_root_squash",
                      "world-readable export check"],
    "docker":        ["check unauthenticated API (:2375)",
                      "list containers", "container escape assessment"],
    "telnet":        ["credential brute force", "cleartext credential capture"],
}

class KnowledgeBase:
    def __init__(self, path: Path = _KB_PATH):
        self._path = path
        self._kb: dict[str, list[str]] = dict(_SEED)
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
