"""
QRShield – Context Engine
Analyses the *surrounding context* of a QR scan to surface additional
fraud signals that are invisible from the payload alone.

Context dimensions:
  1. Temporal   – time of day, day of week, unusual scan hours
  2. Geolocation – country/region risk, VPN/Tor IP, mismatch with merchant
  3. Device      – user-agent heuristics, headless browser hints
  4. Behavioural – scan frequency, repeated identical QRs, rapid-fire scans
  5. Network     – public Wi-Fi, IP reputation (optional)

All analysis is rule-based.  No ML.  Optional IP enrichment calls are
made only when the caller supplies the relevant config keys.

Input: ScanContext  (populated by the API layer from request headers / body)
Output: ContextAnalysisResult  (findings + score contribution)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from app.config import settings
from app.core.url_analyzer import Finding, Severity, SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)


# ── Input schema ──────────────────────────────────────────────────────────────

@dataclass
class ScanContext:
    """
    Caller-supplied context about the scan environment.
    All fields are optional; missing data simply means fewer checks.
    """
    # Temporal
    scan_timestamp: Optional[datetime] = None   # UTC preferred; naive ok

    # Network / IP
    client_ip: Optional[str] = None             # IPv4 or IPv6
    is_wifi: Optional[bool] = None              # True = connected via Wi-Fi
    wifi_ssid: Optional[str] = None             # SSID if available

    # Geo (caller-supplied or derived from IP)
    country_code: Optional[str] = None          # ISO-3166-1 alpha-2, e.g. "IN"
    region: Optional[str] = None

    # Device
    user_agent: Optional[str] = None
    device_type: Optional[str] = None           # "mobile" | "desktop" | "tablet"

    # Behavioural (caller tracks and passes these in)
    scans_last_minute: int = 0                  # how many QRs scanned in last 60s
    scans_last_hour: int = 0
    same_payload_count: int = 0                 # times this exact payload seen recently

    # Payment-specific
    merchant_country: Optional[str] = None      # country where merchant is registered
    declared_amount: Optional[float] = None     # amount shown to user (UI layer)


# ── Output schema ─────────────────────────────────────────────────────────────

@dataclass
class ContextAnalysisResult:
    findings: List[Finding] = field(default_factory=list)
    raw_score_contribution: int = 0
    enriched_country: Optional[str] = None      # from IP lookup if not supplied
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_proxy: Optional[bool] = None

    def add(self, rule: str, severity: Severity,
            description: str, evidence: Optional[str] = None) -> None:
        self.findings.append(Finding(rule, severity, description, evidence))
        self.raw_score_contribution += SEVERITY_WEIGHTS[severity]


# ── Reference data ────────────────────────────────────────────────────────────

# Countries with elevated payment-fraud rates (ISO-3166-1 alpha-2)
# Source: industry reports – list is illustrative, not exhaustive
HIGH_RISK_COUNTRIES = {
    "NG", "GH", "CI", "CM",          # West Africa
    "RO", "BG", "MD",                 # Eastern Europe
    "VN", "ID", "PH",                 # South-East Asia (card fraud rates)
    "BR", "CO",                        # Latin America
    "PK", "BD",                        # South Asia neighbours with elevated risk
    "UA", "RU",                        # Geopolitical risk + cybercrime
}

# Countries that commonly host QR-payment fraud targeting India
TARGETING_INDIA_COUNTRIES = {"CN", "PK", "NG", "RO"}

# User-agent signals that suggest non-human / testing environments
HEADLESS_UA_PATTERNS = [
    "headlesschrome", "phantomjs", "selenium", "puppeteer",
    "playwright", "python-httpx", "python-requests", "curl",
    "wget", "go-http-client", "java/",
]

# Peak fraud hours (UTC) based on common fraud-pattern research
# Fraudsters often operate at night local time to avoid scrutiny
SUSPICIOUS_HOURS_UTC = {0, 1, 2, 3, 4, 22, 23}

# Indian Standard Time offset from UTC (UTC+5:30)
IST_OFFSET_HOURS = 5.5

# Velocity limits
MAX_SCANS_PER_MINUTE = 5
MAX_SCANS_PER_HOUR   = 30


# ── Check implementations ─────────────────────────────────────────────────────

def _check_temporal(ctx: ScanContext, result: ContextAnalysisResult) -> None:
    """Flag unusual scan times."""
    if not ctx.scan_timestamp:
        return

    ts = ctx.scan_timestamp
    # Normalise to UTC-aware if naive
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    hour_utc = ts.hour
    # Approximate IST hour (India is primary target market)
    hour_ist = (hour_utc + IST_OFFSET_HOURS) % 24

    # Late-night / early-morning in IST
    if 0 <= hour_ist < 5:
        result.add(
            "LATE_NIGHT_SCAN", Severity.LOW,
            f"QR scanned at {hour_ist:.0f}:xx IST (late night / early morning). "
            "Payment QRs scanned between midnight and 5 AM are statistically "
            "associated with fraud attempts.",
            evidence=f"IST hour ≈ {hour_ist:.0f}",
        )

    # Suspicious UTC hours (e.g. coordinated overseas fraud campaigns)
    if hour_utc in SUSPICIOUS_HOURS_UTC:
        result.add(
            "SUSPICIOUS_UTC_HOUR", Severity.INFO,
            f"Scan occurred at UTC {hour_utc:02d}:xx, a peak hour for "
            "cross-border fraud campaigns.",
            evidence=f"UTC hour = {hour_utc}",
        )

    # Weekend late-night is even riskier
    weekday = ts.weekday()   # 0=Monday … 6=Sunday
    if weekday in (4, 5, 6) and 0 <= hour_ist < 5:
        result.add(
            "WEEKEND_LATE_NIGHT_SCAN", Severity.MEDIUM,
            "QR scanned on a weekend between midnight–5 AM IST. "
            "Fraud operators often exploit reduced oversight on weekends.",
            evidence=f"weekday={weekday}, IST hour≈{hour_ist:.0f}",
        )


def _check_geo(ctx: ScanContext, result: ContextAnalysisResult) -> None:
    """Flag geographic risk signals."""
    country = (result.enriched_country or ctx.country_code or "").upper()
    merchant_country = (ctx.merchant_country or "IN").upper()

    if not country:
        return

    if country in HIGH_RISK_COUNTRIES:
        result.add(
            "HIGH_RISK_COUNTRY", Severity.MEDIUM,
            f"Scan originated from '{country}', which has an elevated payment "
            "fraud risk profile.",
            evidence=country,
        )

    if country in TARGETING_INDIA_COUNTRIES and merchant_country == "IN":
        result.add(
            "CROSS_BORDER_INDIA_FRAUD_RISK", Severity.HIGH,
            f"Scan originated from '{country}' for an India-registered merchant. "
            "This origin country is associated with QR-payment scams targeting India.",
            evidence=f"scan_country={country}, merchant_country={merchant_country}",
        )

    # Geo mismatch: user country ≠ merchant country
    if country and merchant_country and country != merchant_country:
        result.add(
            "GEO_MISMATCH", Severity.MEDIUM,
            f"Scan country '{country}' does not match merchant country "
            f"'{merchant_country}'. Cross-border payment QRs warrant extra scrutiny.",
            evidence=f"{country} ≠ {merchant_country}",
        )


def _check_device(ctx: ScanContext, result: ContextAnalysisResult) -> None:
    """Flag suspicious device / user-agent signals."""
    ua = (ctx.user_agent or "").lower()

    if not ua:
        result.add(
            "MISSING_USER_AGENT", Severity.INFO,
            "No User-Agent provided. Automated / scripted scanning tools "
            "often omit the User-Agent header.",
        )
        return

    for pattern in HEADLESS_UA_PATTERNS:
        if pattern in ua:
            result.add(
                "HEADLESS_BROWSER_UA", Severity.HIGH,
                f"User-Agent matches automated tool pattern '{pattern}'. "
                "Legitimate users do not scan QR codes with headless browsers.",
                evidence=ua[:100],
            )
            return

    # Desktop scanning a mobile payment QR is unusual
    if ctx.device_type == "desktop":
        result.add(
            "DESKTOP_PAYMENT_SCAN", Severity.LOW,
            "QR payment scan from a desktop device is unusual. "
            "Most legitimate payment QR scans originate from mobile devices.",
        )

    # Very old or generic UA
    if "mozilla/4.0" in ua and "compatible" in ua and "msie" in ua:
        result.add(
            "LEGACY_BROWSER_UA", Severity.LOW,
            "Request claims to be Internet Explorer / legacy browser – "
            "inconsistent with modern mobile payment apps.",
            evidence=ua[:80],
        )


def _check_network(ctx: ScanContext, result: ContextAnalysisResult) -> None:
    """Flag network-level risk signals."""
    # Public / open Wi-Fi
    if ctx.is_wifi is True:
        ssid = ctx.wifi_ssid or ""
        result.add(
            "WIFI_PAYMENT_SCAN", Severity.LOW,
            "Payment QR scanned over a Wi-Fi connection. "
            "Public Wi-Fi networks may allow MITM attacks or QR substitution.",
            evidence=f"SSID: {ssid}" if ssid else None,
        )

        # Common public hotspot SSIDs
        PUBLIC_WIFI_PATTERNS = [
            "airport", "hotel", "cafe", "coffee", "library",
            "free", "public", "guest", "open", "mall",
        ]
        if any(p in ssid.lower() for p in PUBLIC_WIFI_PATTERNS):
            result.add(
                "PUBLIC_WIFI_DETECTED", Severity.MEDIUM,
                f"SSID '{ssid}' suggests a public hotspot. Payment transactions "
                "over public Wi-Fi are high-risk.",
                evidence=ssid,
            )


def _check_vpn_tor(result: ContextAnalysisResult) -> None:
    """Surface VPN/Tor flags already enriched by IP lookup."""
    if result.is_tor:
        result.add(
            "TOR_EXIT_NODE", Severity.HIGH,
            "Request originated from a Tor exit node. "
            "Tor is used to anonymise fraudulent transactions.",
        )
    if result.is_vpn:
        result.add(
            "VPN_DETECTED", Severity.MEDIUM,
            "Request originated from a known VPN/proxy IP. "
            "Legitimate payment scans rarely use VPNs.",
        )


def _check_velocity(ctx: ScanContext, result: ContextAnalysisResult) -> None:
    """Flag high-frequency scanning behaviour."""
    if ctx.scans_last_minute > MAX_SCANS_PER_MINUTE:
        result.add(
            "HIGH_SCAN_VELOCITY_MINUTE", Severity.HIGH,
            f"{ctx.scans_last_minute} QR codes scanned in the last 60 seconds "
            f"(limit: {MAX_SCANS_PER_MINUTE}). "
            "High scan velocity suggests automated or scripted behaviour.",
            evidence=f"{ctx.scans_last_minute} scans/min",
        )

    if ctx.scans_last_hour > MAX_SCANS_PER_HOUR:
        result.add(
            "HIGH_SCAN_VELOCITY_HOUR", Severity.MEDIUM,
            f"{ctx.scans_last_hour} QR codes scanned in the last hour "
            f"(limit: {MAX_SCANS_PER_HOUR}).",
            evidence=f"{ctx.scans_last_hour} scans/hr",
        )

    if ctx.same_payload_count > 3:
        result.add(
            "REPEATED_PAYLOAD", Severity.MEDIUM,
            f"This exact QR payload has been scanned {ctx.same_payload_count} "
            "times recently. Repeated scanning of the same QR code may indicate "
            "a replay or confusion attack.",
            evidence=f"count={ctx.same_payload_count}",
        )


# ── Optional IP enrichment (ip-api.com – free tier, no key required) ─────────

async def _enrich_ip(
    ip: str, result: ContextAnalysisResult
) -> None:
    """
    Look up IP metadata using ip-api.com (free, no API key needed).
    Populates country, VPN/proxy/Tor flags on the result.
    Falls back silently on any network error.
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return

    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,country,countryCode,proxy,hosting,query"
    )
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            resp = await client.get(url)
        data = resp.json()
        if data.get("status") == "success":
            result.enriched_country = data.get("countryCode", "")
            # ip-api "proxy" field covers VPN + proxy + Tor
            is_proxy = bool(data.get("proxy"))
            is_hosting = bool(data.get("hosting"))
            if is_proxy:
                result.is_vpn = True
            if is_hosting:
                result.is_proxy = True
    except Exception as exc:
        logger.debug("IP enrichment failed for %s: %s", ip, exc)


# ── Public entry-point ────────────────────────────────────────────────────────

async def analyse_context(ctx: ScanContext) -> ContextAnalysisResult:
    """
    Run all context checks and return a ContextAnalysisResult.
    Async because optional IP enrichment makes a network call.
    """
    result = ContextAnalysisResult()

    # IP enrichment first so geo checks can use enriched country
    if settings.enable_geo_context and ctx.client_ip:
        await _enrich_ip(ctx.client_ip, result)

    # Use enriched country to back-fill ctx for geo checks
    if not ctx.country_code and result.enriched_country:
        ctx.country_code = result.enriched_country

    if settings.enable_time_context:
        _check_temporal(ctx, result)

    if settings.enable_geo_context:
        _check_geo(ctx, result)
        _check_vpn_tor(result)

    if settings.enable_device_context:
        _check_device(ctx, result)

    _check_network(ctx, result)
    _check_velocity(ctx, result)

    return result
