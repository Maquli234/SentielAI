"""
SentinelAI CVE Intelligence Engine
=====================================
Queries public vulnerability databases for service/version information.

Supported sources:
  • NVD NIST API v2 (free, no key required for basic queries)
  • Local knowledge base (config.OUTDATED_VERSIONS) as offline fallback

NOTE: All lookups are read-only reconnaissance.
      No exploitation is performed.
"""

import json
import logging
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sentinelai.cve_lookup")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY    = 6.0   # NVD rate limit: 5 req/30 s without API key


@dataclass
class CVEEntry:
    cve_id:      str
    description: str
    cvss_score:  Optional[float]
    cvss_vector: str
    severity:    str
    published:   str
    references:  list[str] = field(default_factory=list)

    def __str__(self) -> str:
        score = f"CVSS {self.cvss_score}" if self.cvss_score else "No CVSS"
        return f"{self.cve_id}  [{self.severity}  {score}]  {self.description[:80]}"


@dataclass
class CVELookupResult:
    query:      str
    cves:       list[CVEEntry] = field(default_factory=list)
    source:     str = "nvd"
    error:      Optional[str] = None
    from_cache: bool = False


# ── In-memory cache (per-session) ─────────────────────────────────────────────
_CACHE: dict[str, CVELookupResult] = {}


def lookup_service(service: str, version: str = "", max_results: int = 5) -> CVELookupResult:
    """
    Look up CVEs for a service/version string.
    Returns up to *max_results* CVEEntry objects sorted by CVSS score.
    """
    # Build a clean query string
    query = f"{service} {version}".strip()
    cache_key = query.lower()

    if cache_key in _CACHE:
        r = _CACHE[cache_key]
        r.from_cache = True
        return r

    result = _query_nvd(query, max_results)
    _CACHE[cache_key] = result
    return result


def _query_nvd(keyword: str, max_results: int) -> CVELookupResult:
    """Query NVD NIST API v2 for the keyword."""
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 20),
    })
    url = f"{NVD_API_BASE}?{params}"

    logger.debug("NVD query: %s", url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelAI/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        logger.warning("NVD unreachable: %s", exc)
        return CVELookupResult(query=keyword, source="nvd", error=str(exc))
    except Exception as exc:
        logger.error("NVD lookup failed: %s", exc)
        return CVELookupResult(query=keyword, source="nvd", error=str(exc))

    # Respect NVD rate limit
    time.sleep(NVD_DELAY)

    cves: list[CVEEntry] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")

        # Description
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS score (prefer v3.1, fall back to v3.0, then v2)
        cvss_score  = None
        cvss_vector = ""
        severity    = "UNKNOWN"
        metrics     = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_score  = m.get("baseScore")
                cvss_vector = m.get("vectorString", "")
                severity    = (
                    metrics[key][0].get("baseSeverity")
                    or m.get("baseSeverity", "UNKNOWN")
                )
                break

        # Published date
        published = cve_data.get("published", "")[:10]

        # References (top 3)
        refs = [
            r.get("url", "")
            for r in cve_data.get("references", [])[:3]
        ]

        cves.append(CVEEntry(
            cve_id=cve_id,
            description=desc,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity.upper(),
            published=published,
            references=refs,
        ))

    # Sort highest CVSS first
    cves.sort(key=lambda c: c.cvss_score or 0, reverse=True)
    return CVELookupResult(query=keyword, cves=cves[:max_results], source="nvd")


# ── Batch lookup for a full host's open ports ─────────────────────────────────

def lookup_host_services(
    open_ports,   # list of PortInfo
    max_per_service: int = 3,
) -> dict[int, CVELookupResult]:
    """
    Look up CVEs for every service on a host.
    Returns a dict keyed by port number.
    """
    results: dict[int, CVELookupResult] = {}
    for port in open_ports:
        # Skip empty / unrecognised services
        if not port.product and not port.service:
            continue
        # Skip ports with only generic service names and no version
        if port.service in ("tcpwrapped", "unknown") and not port.version:
            continue

        query_svc = port.product or port.service
        query_ver = port.version

        result = lookup_service(query_svc, query_ver, max_per_service)
        results[port.port] = result

        # Small delay between queries to be polite
        time.sleep(1)

    return results
