"""
SentinelAI Web Enumeration Module
===================================
Performs passive web analysis:
  • HTTP header analysis and security header audit
  • Technology / CMS fingerprinting from headers
  • TLS/certificate info extraction
  • Directory brute-force command generation

All operations are read-only reconnaissance against the target.
"""

import urllib.request
import urllib.error
import ssl
import socket
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sentinelai.web_enum")


@dataclass
class SecurityHeaderResult:
    present:  list[str] = field(default_factory=list)
    missing:  list[str] = field(default_factory=list)
    insecure: list[str] = field(default_factory=list)


@dataclass
class WebFingerprint:
    url:           str
    status_code:   int
    server:        str
    powered_by:    str
    technologies:  list[str]       = field(default_factory=list)
    cms:           Optional[str]   = None
    headers:       dict[str, str]  = field(default_factory=dict)
    security_headers: SecurityHeaderResult = field(default_factory=SecurityHeaderResult)
    tls_info:      dict            = field(default_factory=dict)
    error:         Optional[str]   = None


# ── Security headers to check ─────────────────────────────────────────────────
REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INSECURE_PATTERNS = {
    "X-Powered-By": "reveals technology stack",
    "Server":       "reveals server version (if verbose)",
    "X-AspNet-Version": "reveals ASP.NET version",
    "X-AspNetMvc-Version": "reveals MVC version",
}

# ── CMS / framework fingerprints ─────────────────────────────────────────────
CMS_SIGNATURES: dict[str, list[str]] = {
    "WordPress":  ["wp-content", "wp-includes", "wp-login.php"],
    "Drupal":     ["drupal.js", "/sites/default/", "X-Generator: Drupal"],
    "Joomla":     ["/components/", "/modules/", "Joomla!"],
    "Magento":    ["Magento", "mage/cookies.js"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN"],
    "Django":     ["csrfmiddlewaretoken", "Django"],
    "Rails":      ["X-Runtime", "_session_id"],
    "Tomcat":     ["Apache-Coyote", "Tomcat", "JSESSIONID"],
    "IIS":        ["X-Powered-By: ASP.NET", "ASP.NET"],
    "PHP":        ["X-Powered-By: PHP", "PHPSESSID"],
    "Spring":     ["JSESSIONID", "Spring"],
}


def fingerprint(target: str, port: int = 80, https: bool = False) -> WebFingerprint:
    """
    Fetch a web target's root path and extract fingerprinting information.

    Parameters
    ----------
    target : IP address or hostname
    port   : TCP port (default 80)
    https  : use HTTPS if True
    """
    scheme = "https" if https or port == 443 else "http"
    url    = f"{scheme}://{target}:{port}/"

    result = WebFingerprint(url=url, status_code=0, server="", powered_by="")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SentinelAI)"})
        resp = urllib.request.urlopen(req, timeout=10, context=ctx if https else None)
    except urllib.error.HTTPError as exc:
        # Still get headers from error responses
        resp = exc
    except Exception as exc:
        result.error = str(exc)
        logger.warning("Web fingerprint failed for %s: %s", url, exc)
        return result

    result.status_code = resp.status if hasattr(resp, "status") else resp.code
    headers_raw        = dict(resp.headers)

    result.headers     = {k: v for k, v in headers_raw.items()}
    result.server      = headers_raw.get("Server", "")
    result.powered_by  = headers_raw.get("X-Powered-By", "")

    # ── Security header audit ─────────────────────────────────────────────────
    sec = SecurityHeaderResult()
    for h in REQUIRED_HEADERS:
        if h.lower() in {k.lower() for k in headers_raw}:
            sec.present.append(h)
        else:
            sec.missing.append(h)

    for h, reason in INSECURE_PATTERNS.items():
        if h.lower() in {k.lower() for k in headers_raw}:
            val = headers_raw.get(h, "")
            sec.insecure.append(f"{h}: {val}  [{reason}]")

    result.security_headers = sec

    # ── Read body for CMS fingerprinting ─────────────────────────────────────
    try:
        body = resp.read(8192).decode("utf-8", errors="replace")
    except Exception:
        body = ""

    combined_evidence = body + str(headers_raw)

    for cms_name, sigs in CMS_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined_evidence.lower():
                result.cms = cms_name
                result.technologies.append(cms_name)
                break

    # Generic technology detection from headers
    if result.server:
        result.technologies.append(f"Server: {result.server}")
    if result.powered_by:
        result.technologies.append(f"Powered-By: {result.powered_by}")

    # ── TLS info ──────────────────────────────────────────────────────────────
    if https or port == 443:
        result.tls_info = _get_tls_info(target, port)

    return result


def _get_tls_info(host: str, port: int) -> dict:
    """Extract TLS certificate information."""
    try:
        ctx  = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert    = ssock.getpeercert()
                cipher  = ssock.cipher()
                version = ssock.version()
        return {
            "version":    version,
            "cipher":     cipher[0] if cipher else "",
            "subject":    dict(x[0] for x in cert.get("subject", [])) if cert else {},
            "issuer":     dict(x[0] for x in cert.get("issuer", [])) if cert else {},
            "not_after":  cert.get("notAfter", "") if cert else "",
            "sans":       cert.get("subjectAltName", []) if cert else [],
        }
    except Exception as exc:
        return {"error": str(exc)}


def generate_web_suggestions(fp: WebFingerprint, target: str) -> list[str]:
    """Generate next-step suggestions from a WebFingerprint."""
    suggestions = []
    base = fp.url

    suggestions.append(f"Directory brute-force:     gobuster dir -u {base} -w /usr/share/wordlists/dirb/common.txt")
    suggestions.append(f"Web vulnerability scan:    nikto -h {base}")
    suggestions.append(f"Technology scan:           whatweb {base}")
    suggestions.append(f"Fuzzing:                   ffuf -u {base}FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")

    if fp.cms:
        cms_lower = fp.cms.lower()
        if "wordpress" in cms_lower:
            suggestions.append(f"WordPress scan:            wpscan --url {base} --enumerate vp,u")
        elif "drupal" in cms_lower:
            suggestions.append(f"Drupal scan:               droopescan scan drupal -u {base}")
        elif "joomla" in cms_lower:
            suggestions.append(f"Joomla scan:               joomscan --url {base}")

    if fp.tls_info and not fp.tls_info.get("error"):
        suggestions.append(f"TLS audit:                 sslscan {target}")
        suggestions.append(f"Full TLS test:             testssl.sh {target}")

    if fp.security_headers.missing:
        suggestions.append(
            f"Missing security headers:  {', '.join(fp.security_headers.missing[:3])}"
        )

    return suggestions
