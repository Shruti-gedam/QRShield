"""
QRShield – Payload Parser Module
Parses and validates QR code payloads across all supported formats.

Supported formats:
  - UPI Intent URL  (upi://pay?...)
  - HTTPS / HTTP    (web payment pages)
  - Payment deep-links (paytm://, phonepe://, gpay://, bhim://, etc.)
  - Plain text      (raw VPA, phone numbers, transaction refs)
  - vCard           (contact sharing – sometimes abused)
  - WiFi            (WIFI:S:...;T:...;P:...;)
  - Geo coordinates (geo:lat,lon)
  - Mailto / Tel

Each parser extracts structured fields and runs format-specific
fraud-heuristic checks that feed into the risk scoring engine.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from app.core.url_analyzer import Finding, Severity, SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)


# ── Result types ──────────────────────────────────────────────────────────────

class ParseStatus(str, Enum):
    OK       = "ok"
    PARTIAL  = "partial"   # parsed but with warnings
    MALFORMED = "malformed"
    UNKNOWN  = "unknown"


@dataclass
class ParsedPayload:
    format: str                              # "upi", "url", "deep_link", "text", …
    status: ParseStatus
    fields: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    raw_score_contribution: int = 0
    error: Optional[str] = None

    def add(self, rule: str, severity: Severity, description: str,
            evidence: Optional[str] = None) -> None:
        self.findings.append(Finding(rule, severity, description, evidence))
        self.raw_score_contribution += SEVERITY_WEIGHTS[severity]


# ── UPI helpers ───────────────────────────────────────────────────────────────

# Official UPI VPA regex: localpart@bankhandle
_VPA_RE = re.compile(
    r"^[a-zA-Z0-9.\-_+]{2,256}@[a-zA-Z]{2,64}$"
)

# Known legitimate NPCI-registered bank handles
_KNOWN_UPI_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi",
    "upi", "paytm", "ybl", "ibl", "axl",
    "apl", "fbl", "pingpay", "jupiteraxis",
    "kotak", "icici", "sbi", "hdfcbank", "axis",
    "indus", "airtel", "jio", "boi", "cnrb",
    "federal", "idbi", "pnb", "union", "ucoin",
}

# Characters that should never appear in a VPA
_VPA_ILLEGAL_RE = re.compile(r"[<>\"'`{}|\\^~\[\]]")

def _parse_upi(payload: str) -> ParsedPayload:
    """
    Parse a UPI Intent URL: upi://pay?pa=VPA&pn=NAME&am=AMOUNT&...
    Spec: https://www.npci.org.in/PDF/npci/upi/circular/2017/UPI_Circular05.pdf
    """
    result = ParsedPayload(format="upi", status=ParseStatus.OK)

    try:
        parsed = urlparse(payload)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    except Exception as exc:
        result.status = ParseStatus.MALFORMED
        result.error = f"UPI URL parse error: {exc}"
        return result

    # ── Required fields ────────────────────────────────────────────────────
    pa = params.get("pa", "").strip()       # Payee VPA
    pn = params.get("pn", "").strip()       # Payee Name
    am = params.get("am", "").strip()       # Amount
    cu = params.get("cu", "INR").strip()    # Currency
    tn = params.get("tn", "").strip()       # Transaction Note
    tr = params.get("tr", "").strip()       # Transaction Ref

    result.fields = {
        "vpa": pa, "payee_name": pn, "amount": am,
        "currency": cu, "note": tn, "ref": tr,
        "all_params": params,
    }

    # ── VPA checks ─────────────────────────────────────────────────────────
    if not pa:
        result.add(
            "UPI_MISSING_VPA", Severity.CRITICAL,
            "UPI payload is missing the 'pa' (payee VPA) parameter. "
            "This is required by the UPI specification.",
        )
        result.status = ParseStatus.MALFORMED
    else:
        if not _VPA_RE.match(pa):
            result.add(
                "UPI_INVALID_VPA_FORMAT", Severity.HIGH,
                f"Payee VPA '{pa}' does not match the standard format "
                "'localpart@bankhandle'.",
                evidence=pa,
            )
        else:
            handle = pa.split("@", 1)[-1].lower()
            if handle not in _KNOWN_UPI_HANDLES:
                result.add(
                    "UPI_UNKNOWN_HANDLE", Severity.LOW,
                    f"UPI handle '@{handle}' is not in the known NPCI-registered "
                    "handle list. May be a new or private handle — verify before paying.",
                    evidence=handle,
                )

        if _VPA_ILLEGAL_RE.search(pa):
            result.add(
                "UPI_VPA_ILLEGAL_CHARS", Severity.HIGH,
                "VPA contains illegal characters that could indicate injection.",
                evidence=pa,
            )

        # Excessive length
        if len(pa) > 100:
            result.add(
                "UPI_VPA_TOO_LONG", Severity.MEDIUM,
                f"VPA is {len(pa)} characters – far beyond normal length.",
                evidence=pa,
            )

    # ── Amount checks ──────────────────────────────────────────────────────
    if am:
        try:
            amount_val = float(am)
            if amount_val < 0:
                result.add(
                    "UPI_NEGATIVE_AMOUNT", Severity.HIGH,
                    f"Amount is negative ({am}). UPI payments should never have "
                    "negative amounts — may be a refund scam.",
                    evidence=am,
                )
            elif amount_val == 0:
                result.add(
                    "UPI_ZERO_AMOUNT", Severity.MEDIUM,
                    "Amount is zero. Scammers sometimes use zero-amount QRs to "
                    "authorise token collection before charging later.",
                    evidence=am,
                )
            elif amount_val > 100_000:
                result.add(
                    "UPI_HIGH_AMOUNT", Severity.MEDIUM,
                    f"Amount ₹{amount_val:,.2f} exceeds ₹1,00,000. Verify this is "
                    "intentional – most daily-use transactions are much lower.",
                    evidence=am,
                )
        except ValueError:
            result.add(
                "UPI_INVALID_AMOUNT", Severity.HIGH,
                f"Amount field '{am}' is not a valid number.",
                evidence=am,
            )
    else:
        # No amount — dynamic QR where merchant enters amount; flag for awareness
        result.add(
            "UPI_NO_AMOUNT", Severity.INFO,
            "QR does not specify an amount. Ensure you verify the amount "
            "before confirming the transaction.",
        )

    # ── Currency check ─────────────────────────────────────────────────────
    if cu.upper() != "INR":
        result.add(
            "UPI_NON_INR_CURRENCY", Severity.HIGH,
            f"Currency is set to '{cu}' instead of 'INR'. UPI only supports INR. "
            "Foreign-currency UPI QRs are not valid.",
            evidence=cu,
        )

    # ── Payee name checks ──────────────────────────────────────────────────
    if not pn:
        result.add(
            "UPI_MISSING_PAYEE_NAME", Severity.MEDIUM,
            "Payee name ('pn') is missing. Legitimate merchants always include "
            "a readable payee name.",
        )
    elif len(pn) < 2:
        result.add(
            "UPI_SHORT_PAYEE_NAME", Severity.LOW,
            f"Payee name is only '{pn}' – suspiciously short.",
            evidence=pn,
        )

    # ── Extra undocumented parameters ──────────────────────────────────────
    KNOWN_UPI_PARAMS = {"pa", "pn", "am", "cu", "tn", "tr", "mc", "tid",
                        "url", "mode", "purpose", "orgid", "sign", "refUrl"}
    unknown_params = set(params.keys()) - KNOWN_UPI_PARAMS
    if unknown_params:
        result.add(
            "UPI_UNKNOWN_PARAMS", Severity.LOW,
            f"UPI payload contains non-standard parameters: {unknown_params}. "
            "These may carry tracking data or exploit UPI app parsers.",
            evidence=str(unknown_params),
        )

    # ── Embedded URL in UPI ('url' param) ─────────────────────────────────
    if "url" in params:
        result.add(
            "UPI_EMBEDDED_URL", Severity.MEDIUM,
            "UPI payload includes an embedded 'url' parameter which redirects "
            "to a web page post-payment. Verify the URL is trusted.",
            evidence=params["url"][:80],
        )

    if result.status == ParseStatus.OK and result.findings:
        # Has findings but parsed successfully
        result.status = ParseStatus.PARTIAL

    return result


# ── HTTP/HTTPS parser ─────────────────────────────────────────────────────────

def _parse_http(payload: str) -> ParsedPayload:
    """Light structural parse of an HTTP/S URL payload."""
    result = ParsedPayload(format="url", status=ParseStatus.OK)
    try:
        parsed = urlparse(payload)
        result.fields = {
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
        }
    except Exception as exc:
        result.status = ParseStatus.MALFORMED
        result.error = str(exc)
        return result

    # Fragment used to carry sensitive data
    frag = parsed.fragment or ""
    if any(kw in frag.lower() for kw in ("token", "key", "secret", "auth", "otp")):
        result.add(
            "SENSITIVE_FRAGMENT", Severity.HIGH,
            "URL fragment contains a sensitive keyword. "
            "Sensitive tokens should not be passed in URL fragments.",
            evidence=frag[:80],
        )

    if result.findings:
        result.status = ParseStatus.PARTIAL
    return result


# ── Deep-link parser ──────────────────────────────────────────────────────────

_DEEP_LINK_SCHEMES: Dict[str, str] = {
    "paytm":      "Paytm",
    "phonepe":    "PhonePe",
    "gpay":       "Google Pay",
    "bhim":       "BHIM",
    "amazonpay":  "Amazon Pay",
    "mobikwik":   "MobiKwik",
    "freecharge": "FreeCharge",
    "juspay":     "Juspay",
}

def _parse_deep_link(payload: str) -> ParsedPayload:
    result = ParsedPayload(format="deep_link", status=ParseStatus.OK)
    try:
        parsed = urlparse(payload)
        scheme = parsed.scheme.lower()
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        result.fields = {
            "app": _DEEP_LINK_SCHEMES.get(scheme, scheme),
            "scheme": scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "params": params,
        }
    except Exception as exc:
        result.status = ParseStatus.MALFORMED
        result.error = str(exc)
        return result

    scheme = parsed.scheme.lower()

    if scheme not in _DEEP_LINK_SCHEMES:
        result.add(
            "UNKNOWN_DEEP_LINK_SCHEME", Severity.MEDIUM,
            f"Deep-link scheme '{scheme}://' is not a recognised payment app scheme.",
            evidence=scheme,
        )

    # Many deep-links carry a UPI 'pa' parameter
    pa = params.get("pa", "")
    if pa and not _VPA_RE.match(pa):
        result.add(
            "DEEP_LINK_INVALID_VPA", Severity.HIGH,
            f"Deep-link VPA '{pa}' has an invalid format.",
            evidence=pa,
        )

    # Amount handling same as UPI
    am = params.get("am", "") or params.get("amount", "")
    if am:
        try:
            val = float(am)
            if val < 0:
                result.add(
                    "DEEP_LINK_NEGATIVE_AMOUNT", Severity.HIGH,
                    "Deep-link contains a negative amount.",
                    evidence=am,
                )
        except ValueError:
            result.add(
                "DEEP_LINK_INVALID_AMOUNT", Severity.MEDIUM,
                f"Amount field '{am}' is not numeric.",
                evidence=am,
            )

    if result.findings:
        result.status = ParseStatus.PARTIAL
    return result


# ── vCard parser ──────────────────────────────────────────────────────────────

def _parse_vcard(payload: str) -> ParsedPayload:
    result = ParsedPayload(format="vcard", status=ParseStatus.OK)
    lines = payload.strip().splitlines()
    fields: Dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, _, val = line.partition(":")
            fields[key.strip().upper()] = val.strip()
    result.fields = fields

    # vCards in QR codes used for social engineering
    result.add(
        "VCARD_SOCIAL_ENGINEERING_RISK", Severity.LOW,
        "This QR contains a vCard (contact info). Ensure you trust the source "
        "before saving the contact, as it may be used for social engineering.",
    )

    # Check for URLs embedded in vCard
    urls = [v for k, v in fields.items() if k.startswith("URL")]
    if urls:
        result.add(
            "VCARD_EMBEDDED_URL", Severity.MEDIUM,
            f"vCard contains {len(urls)} embedded URL(s). Verify before visiting.",
            evidence=str(urls[:2]),
        )

    return result


# ── WiFi parser ───────────────────────────────────────────────────────────────

_WIFI_RE = re.compile(
    r"WIFI:(?:T:(?P<type>[^;]*);)?S:(?P<ssid>[^;]*);(?:T:(?P<type2>[^;]*);)?P:(?P<password>[^;]*);",
    re.IGNORECASE,
)

def _parse_wifi(payload: str) -> ParsedPayload:
    result = ParsedPayload(format="wifi", status=ParseStatus.OK)
    m = _WIFI_RE.search(payload)
    if not m:
        result.status = ParseStatus.MALFORMED
        result.error = "Could not parse WiFi QR payload."
        return result

    enc_type = (m.group("type") or m.group("type2") or "").upper()
    ssid     = m.group("ssid") or ""
    password = m.group("password") or ""

    result.fields = {"ssid": ssid, "encryption": enc_type, "password": "***REDACTED***"}

    if enc_type in ("", "nopass"):
        result.add(
            "WIFI_OPEN_NETWORK", Severity.MEDIUM,
            f"WiFi QR connects to open (unencrypted) network '{ssid}'. "
            "Open networks can be used for MITM attacks.",
            evidence=ssid,
        )
    elif enc_type == "WEP":
        result.add(
            "WIFI_WEP_ENCRYPTION", Severity.MEDIUM,
            "WiFi QR uses WEP encryption which is broken and easily cracked.",
        )

    if not password and enc_type not in ("", "nopass"):
        result.add(
            "WIFI_MISSING_PASSWORD", Severity.LOW,
            "WiFi QR specifies encryption but no password – likely malformed.",
        )

    return result


# ── Geo parser ────────────────────────────────────────────────────────────────

_GEO_RE = re.compile(
    r"^geo:(?P<lat>-?\d+\.?\d*),(?P<lon>-?\d+\.?\d*)(?:,(?P<alt>-?\d+\.?\d*))?",
    re.IGNORECASE,
)

def _parse_geo(payload: str) -> ParsedPayload:
    result = ParsedPayload(format="geo", status=ParseStatus.OK)
    m = _GEO_RE.match(payload)
    if not m:
        result.status = ParseStatus.MALFORMED
        result.error = "Could not parse geo: URI."
        return result

    lat = float(m.group("lat"))
    lon = float(m.group("lon"))
    result.fields = {"latitude": lat, "longitude": lon}

    if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        result.add(
            "GEO_INVALID_COORDS", Severity.MEDIUM,
            f"Coordinates ({lat}, {lon}) are out of valid range.",
            evidence=f"lat={lat}, lon={lon}",
        )
    return result


# ── Plain text / VPA parser ───────────────────────────────────────────────────

def _parse_text(payload: str) -> ParsedPayload:
    result = ParsedPayload(format="text", status=ParseStatus.OK)
    stripped = payload.strip()
    result.fields = {"raw": stripped}

    # Looks like a bare VPA without the upi:// scheme?
    if _VPA_RE.match(stripped):
        result.fields["inferred_type"] = "bare_vpa"
        result.add(
            "BARE_VPA", Severity.LOW,
            f"Payload appears to be a UPI VPA ('{stripped}') without the upi:// scheme. "
            "Some apps accept this but it is non-standard.",
            evidence=stripped,
        )

    # Looks like a phone number?
    elif re.match(r"^\+?[0-9 \-().]{7,15}$", stripped):
        result.fields["inferred_type"] = "phone_number"

    # Suspicious: contains 'OTP', 'PIN', 'CVV' in plain text
    sensitive_kw = re.search(
        r"\b(otp|pin|cvv|password|passcode|mpin)\b", stripped, re.IGNORECASE
    )
    if sensitive_kw:
        result.add(
            "SENSITIVE_DATA_IN_TEXT", Severity.CRITICAL,
            f"Plain-text payload contains sensitive keyword '{sensitive_kw.group()}'. "
            "No legitimate QR code should contain OTPs, PINs, or passwords in plain text.",
            evidence=sensitive_kw.group(),
        )

    # Very long text (obfuscation / exploit payload)
    if len(stripped) > 500:
        result.add(
            "LONG_TEXT_PAYLOAD", Severity.MEDIUM,
            f"Text payload is {len(stripped)} characters. Unusually long text "
            "in QR codes may indicate an attempted buffer-overflow exploit.",
        )

    if result.findings:
        result.status = ParseStatus.PARTIAL
    return result


# ── Dispatch table ────────────────────────────────────────────────────────────

def parse_payload(raw: str) -> ParsedPayload:
    """
    Entry point: dispatch to the correct format-specific parser
    based on the payload prefix.
    """
    if not raw or not raw.strip():
        p = ParsedPayload(format="empty", status=ParseStatus.MALFORMED)
        p.error = "Payload is empty."
        return p

    lower = raw.strip().lower()

    if lower.startswith("upi://"):
        return _parse_upi(raw.strip())

    if lower.startswith("http://") or lower.startswith("https://"):
        return _parse_http(raw.strip())

    if lower.startswith("begin:vcard"):
        return _parse_vcard(raw.strip())

    if lower.startswith("wifi:"):
        return _parse_wifi(raw.strip())

    if lower.startswith("geo:"):
        return _parse_geo(raw.strip())

    if lower.startswith("mailto:"):
        p = ParsedPayload(format="mailto", status=ParseStatus.OK)
        p.fields = {"address": raw.strip()[7:]}
        return p

    if lower.startswith("tel:"):
        p = ParsedPayload(format="tel", status=ParseStatus.OK)
        p.fields = {"number": raw.strip()[4:]}
        return p

    # Payment deep-links
    DEEP_SCHEMES = tuple(f"{s}://" for s in _DEEP_LINK_SCHEMES)
    if lower.startswith(DEEP_SCHEMES):
        return _parse_deep_link(raw.strip())

    # Fall back to plain text
    return _parse_text(raw.strip())
