"""
QRShield – URL Analysis Engine
Analyses a URL extracted from a QR code using layered heuristic rules.

Checks performed (all rule-based, no ML):
  1. Scheme safety          – http vs https, unusual schemes
  2. Domain heuristics      – typosquatting, homoglyph, excessive subdomains,
                              IP-address URLs, free-hosting TLDs
  3. URL structure           – abnormal length, suspicious keywords, path depth,
                              encoded characters, obfuscation patterns
  4. Redirect chain          – follows redirects, flags loops / suspicious hops
  5. Domain age / reputation – DNS checks (MX, A records), newly-registered look
  6. External threat feeds   – optional Google Safe Browsing + VirusTotal lookups

Each check returns a list of Finding objects with a severity and description.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import tldextract

from app.config import settings

logger = logging.getLogger(__name__)


# ── Severity / Finding ──────────────────────────────────────────────────────

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.INFO:     0,
    Severity.LOW:      5,
    Severity.MEDIUM:  15,
    Severity.HIGH:    25,
    Severity.CRITICAL: 40,
}


@dataclass
class Finding:
    rule: str
    severity: Severity
    description: str
    evidence: Optional[str] = None


@dataclass
class URLAnalysisResult:
    url: str
    findings: List[Finding] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    final_url: Optional[str] = None          # URL after all redirects
    is_reachable: Optional[bool] = None
    raw_score_contribution: int = 0          # sum of finding weights
    error: Optional[str] = None

    def add(self, rule: str, severity: Severity, description: str,
            evidence: Optional[str] = None) -> None:
        self.findings.append(Finding(rule, severity, description, evidence))
        self.raw_score_contribution += SEVERITY_WEIGHTS[severity]


# ── Known-safe allowlist (expand as needed) ─────────────────────────────────

TRUSTED_PAYMENT_DOMAINS = {
    "paytm.com", "phonepe.com", "googlepay.com", "bhimupi.org.in",
    "upi.npci.org.in", "npci.org.in", "razorpay.com", "cashfree.com",
    "billdesk.com", "payumoney.com", "amazon.in", "flipkart.com",
    "icicibank.com", "hdfcbank.com", "sbi.co.in", "axisbank.com",
    "kotak.com", "yesbank.in", "indusind.com",
}

# ── Suspicious keyword lists ─────────────────────────────────────────────────

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "verification",
    "update", "confirm", "secure", "security", "bank", "wallet",
    "payment", "pay", "checkout", "invoice", "refund", "claim",
    "reward", "prize", "winner", "kyc", "otp", "password", "credential",
    "support", "helpdesk", "customer-care",
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "login", "verify", "account", "update", "banking",
    "wallet", "paypal", "paytm", "phonepe", "gpay", "amazon",
    "flipkart", "hdfc", "sbi", "icici", "axis", "kotak",
]

# Free / abused hosting TLDs and registrars commonly used in phishing
RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq",      # Freenom free TLDs
    "xyz", "top", "click", "link",
    "online", "site", "website", "store",
    "tech", "space", "live",
}

# URL shortener domains (often used to hide final destination)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.io",
    "rebrand.ly", "cutt.ly", "is.gd", "v.gd", "buff.ly", "adf.ly",
    "shorturl.at", "tiny.cc",
}

# Homoglyph / confusable character map (Unicode lookalikes for ASCII)
HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p",  # Cyrillic
    "ο": "o", "α": "a", "β": "b",                         # Greek
    "１": "1", "２": "2", "０": "0",                      # Full-width
})


# ── Rule implementations ──────────────────────────────────────────────────────

def _check_scheme(parsed, result: URLAnalysisResult) -> None:
    scheme = parsed.scheme.lower()
    if scheme == "http":
        result.add(
            "INSECURE_SCHEME", Severity.MEDIUM,
            "URL uses HTTP (unencrypted). Payment links must use HTTPS.",
            evidence=scheme,
        )
    elif scheme not in ("https", "upi", "paytm", "phonepe", "gpay",
                        "bhim", "amazonpay"):
        result.add(
            "UNUSUAL_SCHEME", Severity.HIGH,
            f"Unexpected URL scheme '{scheme}'. May be an exploit or phishing link.",
            evidence=scheme,
        )


def _check_domain(parsed, ext, result: URLAnalysisResult) -> None:
    hostname = parsed.hostname or ""
    registered_domain = ext.registered_domain.lower() if ext.registered_domain else ""
    suffix = ext.suffix.lower() if ext.suffix else ""
    subdomain = ext.subdomain.lower() if ext.subdomain else ""

    # 1. IP address as host
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ip_pattern.match(hostname):
        result.add(
            "IP_ADDRESS_URL", Severity.HIGH,
            "URL uses a raw IP address instead of a domain name. "
            "Legitimate payment services never do this.",
            evidence=hostname,
        )
        return  # further domain checks irrelevant

    # 2. Trusted domain check (fast exit for known-good)
    if registered_domain in TRUSTED_PAYMENT_DOMAINS:
        result.add(
            "TRUSTED_DOMAIN", Severity.INFO,
            f"Domain '{registered_domain}' is on the trusted payment provider list.",
        )
        return

    # 3. Homoglyph / Unicode spoofing
    normalised = hostname.translate(HOMOGLYPH_MAP)
    if normalised != hostname:
        result.add(
            "HOMOGLYPH_DOMAIN", Severity.CRITICAL,
            "Domain contains Unicode lookalike characters that mimic legitimate names.",
            evidence=f"original={hostname}, normalised={normalised}",
        )

    # 4. Punycode / IDN
    if "xn--" in hostname:
        result.add(
            "PUNYCODE_DOMAIN", Severity.HIGH,
            "Domain uses Punycode (internationalised domain name). "
            "Commonly abused for visual spoofing attacks.",
            evidence=hostname,
        )

    # 5. Suspicious keywords in domain
    for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
        if kw in registered_domain and not registered_domain.startswith(kw + "."):
            result.add(
                "BRAND_IN_DOMAIN", Severity.HIGH,
                f"Domain '{registered_domain}' embeds brand keyword '{kw}'. "
                "May be impersonating a legitimate service.",
                evidence=f"keyword={kw}",
            )
            break

    # 6. Excessive subdomain depth
    subdomain_parts = [s for s in subdomain.split(".") if s]
    if len(subdomain_parts) >= 3:
        result.add(
            "DEEP_SUBDOMAIN", Severity.MEDIUM,
            f"URL has {len(subdomain_parts)} subdomain levels. "
            "Deep subdomains are often used to disguise the true domain.",
            evidence=subdomain,
        )

    # 7. Risky TLD
    if suffix in RISKY_TLDS:
        result.add(
            "RISKY_TLD", Severity.MEDIUM,
            f"TLD '.{suffix}' is frequently abused in phishing campaigns.",
            evidence=suffix,
        )

    # 8. URL shortener
    if registered_domain in URL_SHORTENERS:
        result.add(
            "URL_SHORTENER", Severity.MEDIUM,
            "URL uses a shortening service which hides the true destination. "
            "Inspect the redirect chain.",
            evidence=registered_domain,
        )

    # 9. Very long domain name (obfuscation)
    if len(registered_domain) > 30:
        result.add(
            "LONG_DOMAIN", Severity.LOW,
            f"Registered domain is unusually long ({len(registered_domain)} chars). "
            "May be generated to evade blocklists.",
            evidence=registered_domain,
        )

    # 10. Numeric-heavy domain (DGA-like)
    digit_ratio = sum(c.isdigit() for c in registered_domain.replace(".", "")) / max(
        len(registered_domain.replace(".", "")), 1
    )
    if digit_ratio > 0.4:
        result.add(
            "NUMERIC_HEAVY_DOMAIN", Severity.MEDIUM,
            f"Domain is {digit_ratio:.0%} numeric characters. "
            "May be a machine-generated or throwaway domain.",
            evidence=registered_domain,
        )


def _check_url_structure(parsed, result: URLAnalysisResult) -> None:
    full_url = parsed.geturl()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # 1. Excessive total length
    if len(full_url) > 200:
        result.add(
            "LONG_URL", Severity.LOW,
            f"URL is {len(full_url)} characters long. Unusually long URLs can hide "
            "the true destination or carry obfuscated payloads.",
        )

    # 2. Suspicious path keywords
    path_lower = unquote(path).lower()
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", path_lower):
            result.add(
                "SUSPICIOUS_PATH_KEYWORD", Severity.MEDIUM,
                f"Path contains sensitive keyword '{kw}' often found in phishing pages.",
                evidence=kw,
            )
            break  # one finding per URL is enough

    # 3. Encoded / obfuscated characters
    double_encoded = re.findall(r"%25[0-9a-fA-F]{2}", full_url)
    if double_encoded:
        result.add(
            "DOUBLE_ENCODING", Severity.HIGH,
            "URL contains double percent-encoding which is used to evade URL parsers.",
            evidence=str(double_encoded[:3]),
        )

    hex_encoded_domain = re.search(r"https?://(?:%[0-9a-fA-F]{2})+", full_url)
    if hex_encoded_domain:
        result.add(
            "HEX_ENCODED_HOST", Severity.CRITICAL,
            "Hostname is hex-encoded to evade security filters.",
            evidence=hex_encoded_domain.group(),
        )

    # 4. @ symbol in URL (user info injection)
    if "@" in (parsed.netloc or ""):
        result.add(
            "AT_IN_URL", Severity.HIGH,
            "URL contains '@' in the authority component. The part before '@' is "
            "ignored as credentials, masking the real host to the user.",
            evidence=parsed.netloc,
        )

    # 5. Multiple question marks / fragments (potential open-redirect chains)
    if full_url.count("?") > 1:
        result.add(
            "MULTIPLE_QUERY_STRINGS", Severity.LOW,
            "URL contains more than one '?' which may indicate nested redirect parameters.",
        )

    # 6. Query param containing a URL (open redirect)
    if query:
        params = parse_qs(query)
        REDIRECT_PARAMS = {"url", "redirect", "next", "return", "goto",
                           "dest", "destination", "target", "link", "forward"}
        for param in params:
            if param.lower() in REDIRECT_PARAMS:
                result.add(
                    "OPEN_REDIRECT_PARAM", Severity.HIGH,
                    f"Query parameter '{param}' is a known open-redirect parameter. "
                    "May redirect to a malicious page after visiting a trusted domain.",
                    evidence=f"{param}={params[param][0][:80]}",
                )

    # 7. Deep path depth
    path_parts = [p for p in path.split("/") if p]
    if len(path_parts) > 6:
        result.add(
            "DEEP_PATH", Severity.LOW,
            f"URL path has {len(path_parts)} segments. Very deep paths are uncommon "
            "in legitimate payment flows.",
        )

    # 8. Fragment used as redirect
    if fragment and fragment.lower().startswith("http"):
        result.add(
            "FRAGMENT_REDIRECT", Severity.HIGH,
            "URL fragment starts with 'http', indicating a redirect hidden in the "
            "hash portion (invisible to many security tools).",
            evidence=fragment[:80],
        )


def _check_dns(hostname: str, result: URLAnalysisResult) -> None:
    """Lightweight DNS checks — purely local, no external API required."""
    if not hostname:
        return
    try:
        import dns.resolver
        # Check for MX records (legitimate payment sites always have email)
        try:
            dns.resolver.resolve(hostname, "MX", lifetime=3)
        except Exception:
            result.add(
                "NO_MX_RECORD", Severity.LOW,
                f"Domain '{hostname}' has no MX record. Legitimate companies "
                "almost always have email configured.",
            )
    except ImportError:
        # dnspython not installed – fall back to basic socket check
        pass

    # Resolve A record – flag if unreachable
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(hostname)
    except socket.gaierror:
        result.add(
            "UNRESOLVABLE_DOMAIN", Severity.HIGH,
            f"Domain '{hostname}' does not resolve to any IP address. "
            "May be a dead phishing domain or DNS typo.",
            evidence=hostname,
        )


async def _follow_redirects(url: str, result: URLAnalysisResult) -> str:
    """
    Async redirect chain follower.
    Returns the final URL after all redirects.
    Flags suspicious intermediate hops.
    """
    chain: List[str] = [url]
    current = url
    max_hops = settings.max_redirect_follow
    timeout = settings.redirect_timeout_seconds

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            verify=False,           # noqa: S501 – intentional for analysis
            headers={"User-Agent": "QRShield-Scanner/1.0"},
        ) as client:
            for _ in range(max_hops):
                try:
                    resp = await client.head(current)
                except httpx.RequestError:
                    # Try GET if HEAD fails (some servers reject HEAD)
                    try:
                        resp = await client.get(current)
                    except httpx.RequestError as exc:
                        result.add(
                            "REDIRECT_UNREACHABLE", Severity.MEDIUM,
                            f"Could not reach '{current}' during redirect chain follow.",
                            evidence=str(exc),
                        )
                        break

                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Absolute vs relative redirect
                    if location.startswith("/"):
                        parsed = urlparse(current)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    chain.append(location)

                    # Cross-domain redirect is suspicious in payment flows
                    from_domain = tldextract.extract(current).registered_domain
                    to_domain   = tldextract.extract(location).registered_domain
                    if from_domain and to_domain and from_domain != to_domain:
                        result.add(
                            "CROSS_DOMAIN_REDIRECT", Severity.MEDIUM,
                            f"Redirect crosses domain boundary: "
                            f"'{from_domain}' → '{to_domain}'.",
                            evidence=f"{current[:60]} → {location[:60]}",
                        )
                    current = location
                else:
                    break   # no more redirects

    except Exception as exc:
        result.add(
            "REDIRECT_CHAIN_ERROR", Severity.LOW,
            "Error while following redirect chain.",
            evidence=str(exc),
        )

    if len(chain) > 3:
        result.add(
            "LONG_REDIRECT_CHAIN", Severity.MEDIUM,
            f"URL redirects {len(chain) - 1} time(s) before reaching destination. "
            "Long redirect chains are used to evade link scanners.",
            evidence=" → ".join(c[:50] for c in chain),
        )

    result.redirect_chain = chain
    result.final_url = chain[-1]
    return chain[-1]


async def _check_safe_browsing(url: str, result: URLAnalysisResult) -> None:
    """Google Safe Browsing API v4 lookup (only when API key is configured)."""
    api_key = settings.safe_browsing_api_key
    if not api_key:
        return

    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )
    body = {
        "client": {"clientId": "qrshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(endpoint, json=body)
            data = resp.json()
        if data.get("matches"):
            threat_types = {m["threatType"] for m in data["matches"]}
            result.add(
                "SAFE_BROWSING_MATCH", Severity.CRITICAL,
                f"Google Safe Browsing flagged this URL: {', '.join(threat_types)}",
                evidence=str(threat_types),
            )
    except Exception as exc:
        logger.warning("Safe Browsing API error: %s", exc)


async def _check_virustotal(url: str, result: URLAnalysisResult) -> None:
    """VirusTotal URL reputation check (only when API key is configured)."""
    api_key = settings.virustotal_api_key
    if not api_key:
        return

    import base64 as _b64
    url_id = _b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(endpoint, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = (
                data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                sev = Severity.CRITICAL if malicious > 3 else Severity.HIGH
                result.add(
                    "VIRUSTOTAL_MATCH", sev,
                    f"VirusTotal: {malicious} engine(s) flagged malicious, "
                    f"{suspicious} flagged suspicious.",
                    evidence=str(stats),
                )
    except Exception as exc:
        logger.warning("VirusTotal API error: %s", exc)


# ── Public async entry-point ──────────────────────────────────────────────────

async def analyse_url(url: str) -> URLAnalysisResult:
    """
    Full async URL analysis pipeline.
    Runs all rule checks and optional external lookups.
    """
    result = URLAnalysisResult(url=url)

    # Basic parse
    try:
        parsed = urlparse(url)
        ext    = tldextract.extract(url)
    except Exception as exc:
        result.error = f"URL parse error: {exc}"
        return result

    hostname = parsed.hostname or ""

    # Run synchronous rule checks
    _check_scheme(parsed, result)
    _check_domain(parsed, ext, result)
    _check_url_structure(parsed, result)
    _check_dns(hostname, result)

    # Async checks (redirect chain + optional threat feeds)
    await asyncio.gather(
        _follow_redirects(url, result),
        _check_safe_browsing(url, result),
        _check_virustotal(url, result),
        return_exceptions=True,
    )

    result.is_reachable = result.final_url is not None

    return result
