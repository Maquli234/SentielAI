"""
SentinelAI Subdomain Enumeration Module
=========================================
Passive and active subdomain discovery:
  • DNS brute-force (wordlist-based)
  • Certificate Transparency log query (crt.sh)
  • PTR sweep suggestions

All lookups are passive or standard DNS queries.
"""

import socket
import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

logger = logging.getLogger("sentinelai.subdomain_enum")

# Built-in mini wordlist for offline use
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote",
    "dev", "staging", "test", "api", "app", "admin", "portal",
    "webmail", "ns1", "ns2", "dns", "mx", "gateway", "proxy",
    "cdn", "static", "media", "blog", "shop", "store", "support",
    "help", "forum", "community", "gitlab", "github", "jenkins",
    "jira", "confluence", "wiki", "intranet", "extranet", "db",
    "database", "sql", "mysql", "redis", "elastic", "kibana",
    "grafana", "monitor", "nagios", "zabbix", "backup", "files",
]


@dataclass
class SubdomainResult:
    subdomain:  str
    ip_address: Optional[str]
    source:     str     # "brute", "ct_log", "ptr"


@dataclass
class EnumResult:
    domain:     str
    subdomains: list[SubdomainResult] = field(default_factory=list)
    error:      Optional[str]         = None

    @property
    def unique_ips(self) -> list[str]:
        seen = set()
        ips  = []
        for s in self.subdomains:
            if s.ip_address and s.ip_address not in seen:
                seen.add(s.ip_address)
                ips.append(s.ip_address)
        return ips


def enumerate(
    domain: str,
    wordlist: Optional[list[str]] = None,
    max_workers: int = 20,
    use_ct: bool = True,
) -> EnumResult:
    """
    Discover subdomains for *domain*.

    Parameters
    ----------
    domain      : target domain (e.g. example.com)
    wordlist    : list of prefixes to brute-force (uses DEFAULT_WORDLIST if None)
    max_workers : concurrent DNS resolvers
    use_ct      : query crt.sh Certificate Transparency logs
    """
    result = EnumResult(domain=domain)
    words  = wordlist or DEFAULT_WORDLIST

    # ── 1. DNS brute-force ────────────────────────────────────────────────────
    logger.info("DNS brute-force: %d words against %s", len(words), domain)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_resolve, f"{w}.{domain}"): w for w in words}
        for fut in as_completed(futs):
            sub, ip = fut.result()
            if ip:
                result.subdomains.append(
                    SubdomainResult(subdomain=sub, ip_address=ip, source="brute")
                )

    # ── 2. Certificate Transparency (crt.sh) ─────────────────────────────────
    if use_ct:
        ct_subs = _query_crtsh(domain)
        existing = {s.subdomain for s in result.subdomains}
        for sub in ct_subs:
            if sub not in existing:
                ip = _resolve(sub)[1]
                result.subdomains.append(
                    SubdomainResult(subdomain=sub, ip_address=ip, source="ct_log")
                )

    # Deduplicate by subdomain
    seen: set[str] = set()
    unique = []
    for s in result.subdomains:
        if s.subdomain not in seen:
            seen.add(s.subdomain)
            unique.append(s)

    result.subdomains = sorted(unique, key=lambda s: s.subdomain)
    logger.info("Found %d subdomains for %s", len(result.subdomains), domain)
    return result


def _resolve(hostname: str) -> tuple[str, Optional[str]]:
    """Resolve hostname → (hostname, ip_or_None)."""
    try:
        ip = socket.gethostbyname(hostname)
        return hostname, ip
    except (socket.gaierror, socket.herror):
        return hostname, None


def _query_crtsh(domain: str) -> list[str]:
    """Query crt.sh for certificate transparency entries."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req  = urllib.request.Request(url, headers={"User-Agent": "SentinelAI/2.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    subs.add(name)
        return list(subs)
    except Exception as exc:
        logger.warning("crt.sh query failed: %s", exc)
        return []
