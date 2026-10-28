"""
QRShield – Risk Scoring Engine
Aggregates signals from all analysis modules into a single normalised
risk score (0–100) with a human-readable verdict and explanation.

Scoring model (rule-based, no ML):
  ┌─────────────────────────────────────────┬────────────────┐
  │ Source                                  │ Max raw pts    │
  ├─────────────────────────────────────────┼────────────────┤
  │ Payload parser findings                 │ uncapped       │
  │ URL analyzer findings                   │ uncapped       │
  │ Context engine findings                 │ uncapped       │
  │ Decode warnings (binary/truncated)      │ up to +20      │
  │ Payload format risk bonus               │ up to +10      │
  └─────────────────────────────────────────┴────────────────┘

  normalised_score = min(100, round(raw_total / MAX_RAW * 100))

  where MAX_RAW is a calibration constant tuned so that a maximally
  suspicious payload (CRITICAL finding from every module) reaches ~100.

Verdict bands (configurable via settings):
  0–29   → SAFE
  30–59  → SUSPICIOUS
  60–79  → HIGH RISK
  80–100 → CRITICAL / BLOCK

Each verdict also carries:
  - top_findings    : up to 5 highest-severity findings (for UI display)
  - all_findings    : full list for audit log
  - explanation     : plain-English summary paragraph
  - recommendations : actionable steps for the user
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from app.config import settings
from app.core.context_engine import ContextAnalysisResult
from app.core.deception_detector import DeceptionResult
from app.core.payload_parser import ParsedPayload, ParseStatus
from app.core.qr_decoder import DecodeResult, DecodeStatus
from app.core.url_analyzer import Finding, Severity, URLAnalysisResult

logger = logging.getLogger(__name__)


# ── Verdict ───────────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    SAFE     = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK  = "HIGH_RISK"
    CRITICAL   = "CRITICAL"


VERDICT_COLORS = {
    Verdict.SAFE:      "#22c55e",   # green
    Verdict.SUSPICIOUS:"#f59e0b",   # amber
    Verdict.HIGH_RISK: "#ef4444",   # red
    Verdict.CRITICAL:  "#7f1d1d",   # dark red
}

VERDICT_ICONS = {
    Verdict.SAFE:      "✅",
    Verdict.SUSPICIOUS:"⚠️",
    Verdict.HIGH_RISK: "🚨",
    Verdict.CRITICAL:  "🛑",
}

# Calibration: raw score that maps to ~100 after normalisation
# Lowered so that even a single CRITICAL finding (40 pts) + format bonus
# reaches HIGH_RISK territory without needing multiple signals.
_MAX_RAW: int = 100

# Severity ordering for sorting
_SEV_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}

# Extra raw points added per payload format (inherent risk of the format)
_FORMAT_RISK_BONUS: Dict[str, int] = {
    "upi":       0,    # well-structured – risk comes from field values
    "url":       5,    # web URLs have more attack surface
    "deep_link": 3,
    "text":      8,    # unstructured – harder to validate
    "vcard":     5,
    "wifi":      5,
    "geo":       0,
    "mailto":    3,
    "tel":       0,
    "unknown":  10,
    "empty":    20,
}


# ── Full analysis result ──────────────────────────────────────────────────────

@dataclass
class RiskReport:
    # Core score
    score: int
    verdict: Verdict
    verdict_color: str
    verdict_icon: str

    # Findings
    all_findings: List[Finding] = field(default_factory=list)
    top_findings: List[Finding] = field(default_factory=list)

    # Human-readable output
    explanation: str = ""
    recommendations: List[str] = field(default_factory=list)

    # Component sub-scores
    payload_score:   int = 0
    url_score:       int = 0
    context_score:   int = 0
    decode_score:    int = 0
    deception_score: int = 0           # ← NEW

    # Pass-through structured data
    decode_result:     Optional[DecodeResult]          = None
    parsed_payload:    Optional[ParsedPayload]         = None
    url_analysis:      Optional[URLAnalysisResult]     = None
    context_analysis:  Optional[ContextAnalysisResult] = None
    deception_result:  Optional[DeceptionResult]       = None   # ← NEW

    # Meta
    analysed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload_format: str = ""
    raw_payload:    Optional[str]   = None
    final_url:      Optional[str]   = None
    redirect_chain: List[str]       = field(default_factory=list)


# ── Score helpers ─────────────────────────────────────────────────────────────

def _normalise(raw: int) -> int:
    """Map raw score to 0–100."""
    return min(100, round(raw / _MAX_RAW * 100))


def _verdict_from_score(score: int) -> Verdict:
    if score < settings.risk_threshold_low:
        return Verdict.SAFE
    if score < settings.risk_threshold_medium:
        return Verdict.SUSPICIOUS
    if score < settings.risk_threshold_high:
        return Verdict.HIGH_RISK
    return Verdict.CRITICAL


def _top_findings(findings: List[Finding], n: int = 5) -> List[Finding]:
    """Return up to n findings sorted by descending severity."""
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity, 0), reverse=True)[:n]


# ── Explanation generator ─────────────────────────────────────────────────────

def _build_explanation(
    verdict: Verdict,
    score: int,
    top: List[Finding],
    fmt: str,
) -> str:
    intro = {
        Verdict.SAFE:      f"This {fmt.upper()} QR code appears safe (risk score {score}/100).",
        Verdict.SUSPICIOUS: f"This {fmt.upper()} QR code is suspicious (risk score {score}/100) "
                             "and requires careful review before proceeding.",
        Verdict.HIGH_RISK:  f"This {fmt.upper()} QR code is HIGH RISK (score {score}/100). "
                             "Do not proceed without thorough verification.",
        Verdict.CRITICAL:   f"CRITICAL – This QR code is almost certainly fraudulent "
                             f"(score {score}/100). Do NOT scan or pay.",
    }[verdict]

    if not top:
        return intro

    bullet_lines = []
    for f in top[:3]:
        bullet_lines.append(f"• [{f.severity.upper()}] {f.description}")

    return intro + "\n\nKey findings:\n" + "\n".join(bullet_lines)


def _build_recommendations(
    verdict: Verdict,
    fmt: str,
    top: List[Finding],
) -> List[str]:
    base: List[str] = []

    if verdict == Verdict.SAFE:
        base.append("No immediate action required. Always verify the payee name before confirming.")
        return base

    if verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK):
        base.append("Do not pay immediately — call the merchant directly to confirm the QR code.")
        base.append("Check the payee name carefully in your payment app before authorising.")

    if verdict == Verdict.CRITICAL:
        base.append("🛑 Do NOT proceed with this payment.")
        base.append("Report this QR code to your bank and to the Cyber Crime Portal (cybercrime.gov.in).")

    # Format-specific advice
    if fmt == "upi":
        base.append("Verify the UPI VPA (@handle) with the merchant in person or over a known phone number.")
    elif fmt == "url":
        base.append("Open the URL only in a sandboxed browser and check the domain carefully.")
    elif fmt == "deep_link":
        base.append("Ensure the payment app is the official version from the Play Store / App Store.")

    # Finding-specific advice
    rule_names = {f.rule for f in top}
    if "URL_SHORTENER" in rule_names:
        base.append("Expand shortened URLs using a tool like unshorten.it before visiting.")
    if "CROSS_DOMAIN_REDIRECT" in rule_names or "LONG_REDIRECT_CHAIN" in rule_names:
        base.append("This URL redirects multiple times — the final destination may differ from what is shown.")
    if "SAFE_BROWSING_MATCH" in rule_names or "VIRUSTOTAL_MATCH" in rule_names:
        base.append("This URL has been flagged by security databases — treat it as malicious.")
    if "HOMOGLYPH_DOMAIN" in rule_names or "PUNYCODE_DOMAIN" in rule_names:
        base.append("The domain uses look-alike characters to impersonate a trusted site.")
    if "TOR_EXIT_NODE" in rule_names or "VPN_DETECTED" in rule_names:
        base.append("The request origin has been anonymised — treat this scan with extra suspicion.")
    if "UPI_ZERO_AMOUNT" in rule_names:
        base.append("Zero-amount UPI QRs are sometimes used to collect device tokens; decline this request.")
    if "PAY_RECEIVE_MISMATCH" in rule_names or "FAKE_VERIFICATION_PAYMENT" in rule_names:
        base.append("The message claims you will RECEIVE money but the QR initiates a PAYMENT. This is a common scam.")
    if "AMOUNT_MISMATCH" in rule_names:
        base.append("The amount in the message does not match the QR — verify the exact amount before paying.")
    if "URGENCY_MANIPULATION" in rule_names:
        base.append("Ignore urgency pressure. Legitimate payments are never time-limited emergencies.")
    if "AUTHORITY_SPOOFING" in rule_names:
        base.append("No government or bank will ever ask you to scan a QR code. This is a scam.")

    return base


# ── Decode-level risk ─────────────────────────────────────────────────────────

def _decode_raw_score(decode: DecodeResult) -> int:
    """Convert decode warnings into a raw score contribution."""
    pts = 0
    if decode.status == DecodeStatus.FAILED:
        return 0   # nothing to score
    for w in decode.warnings:
        wl = w.lower()
        if "non-printable" in wl or "binary" in wl:
            pts += 15
        elif "truncated" in wl:
            pts += 10
        elif "multiple" in wl:
            pts += 5
        else:
            pts += 2
    return min(pts, 20)


# ── Main scoring function ─────────────────────────────────────────────────────

def compute_risk(
    decode: DecodeResult,
    parsed: ParsedPayload,
    url_analysis: Optional[URLAnalysisResult],
    context: Optional[ContextAnalysisResult],
    deception: Optional[DeceptionResult] = None,
) -> RiskReport:
    """
    Aggregate all module outputs into a final RiskReport.
    This function is synchronous — all async work is done by the callers.
    """

    all_findings: List[Finding] = []

    # ── Collect findings ───────────────────────────────────────────────────
    payload_raw   = parsed.raw_score_contribution
    url_raw       = url_analysis.raw_score_contribution if url_analysis else 0
    context_raw   = context.raw_score_contribution      if context      else 0
    decode_raw    = _decode_raw_score(decode)
    deception_raw = deception.raw_score_contribution    if deception    else 0

    all_findings.extend(parsed.findings)
    if url_analysis:
        all_findings.extend(url_analysis.findings)
    if context:
        all_findings.extend(context.findings)
    if deception:
        all_findings.extend(deception.findings)

    # Decode warnings as pseudo-findings
    for w in decode.warnings:
        all_findings.append(Finding(
            rule="DECODE_WARNING",
            severity=Severity.LOW,
            description=w,
        ))

    # ── Format risk bonus ──────────────────────────────────────────────────
    fmt = parsed.format or "unknown"
    format_bonus = _FORMAT_RISK_BONUS.get(fmt, 5)

    if parsed.status == ParseStatus.MALFORMED:
        format_bonus += 20
        all_findings.append(Finding(
            rule="MALFORMED_PAYLOAD",
            severity=Severity.HIGH,
            description=f"The {fmt.upper()} payload is malformed and could not be "
                        "fully parsed. Malformed QR payloads are a common fraud signal.",
        ))

    # ── Deception override: if PAY/RECEIVE mismatch detected, force CRITICAL ──
    force_critical = deception is not None and deception.is_deceptive and deception_raw >= 40

    # ── Total raw + normalise ──────────────────────────────────────────────
    raw_total = payload_raw + url_raw + context_raw + decode_raw + deception_raw + format_bonus
    score     = _normalise(raw_total)
    if force_critical:
        score = max(score, 80)          # ensure at least CRITICAL band
    verdict   = _verdict_from_score(score)

    # Sub-scores
    p_score = _normalise(payload_raw)
    u_score = _normalise(url_raw)
    c_score = _normalise(context_raw)
    d_score = _normalise(decode_raw)
    dec_score = _normalise(deception_raw)

    top = _top_findings(all_findings)
    explanation = _build_explanation(verdict, score, top, fmt)
    recommendations = _build_recommendations(verdict, fmt, top)

    return RiskReport(
        score=score,
        verdict=verdict,
        verdict_color=VERDICT_COLORS[verdict],
        verdict_icon=VERDICT_ICONS[verdict],
        all_findings=all_findings,
        top_findings=top,
        explanation=explanation,
        recommendations=recommendations,
        payload_score=p_score,
        url_score=u_score,
        context_score=c_score,
        decode_score=d_score,
        deception_score=dec_score,
        decode_result=decode,
        parsed_payload=parsed,
        url_analysis=url_analysis,
        context_analysis=context,
        deception_result=deception,
        payload_format=fmt,
        raw_payload=decode.raw_payload,
        final_url=url_analysis.final_url if url_analysis else None,
        redirect_chain=url_analysis.redirect_chain if url_analysis else [],
    )


# ── Serialiser (plain dict for JSON responses) ────────────────────────────────

def report_to_dict(report: RiskReport) -> Dict[str, Any]:
    """Convert RiskReport to a JSON-serialisable dict."""

    def finding_to_dict(f: Finding) -> Dict[str, Any]:
        return {
            "rule": f.rule,
            "severity": f.severity.value,
            "description": f.description,
            "evidence": f.evidence,
        }

    decode = report.decode_result
    parsed = report.parsed_payload
    url    = report.url_analysis
    ctx    = report.context_analysis

    return {
        # ── Score & verdict ────────────────────────────────────────────
        "score": report.score,
        "verdict": report.verdict.value,
        "verdict_color": report.verdict_color,
        "verdict_icon": report.verdict_icon,
        "explanation": report.explanation,
        "recommendations": report.recommendations,

        # ── Sub-scores ─────────────────────────────────────────────────
        "sub_scores": {
            "payload":   report.payload_score,
            "url":       report.url_score,
            "context":   report.context_score,
            "decode":    report.decode_score,
            "deception": report.deception_score,
        },

        # ── Findings ───────────────────────────────────────────────────
        "top_findings":  [finding_to_dict(f) for f in report.top_findings],
        "all_findings":  [finding_to_dict(f) for f in report.all_findings],

        # ── Payload info ───────────────────────────────────────────────
        "payload": {
            "format":      report.payload_format,
            "raw":         report.raw_payload,
            "status":      parsed.status.value if parsed else None,
            "fields":      _safe_fields(parsed.fields if parsed else {}),
        },

        # ── URL info ───────────────────────────────────────────────────
        "url_analysis": {
            "final_url":      report.final_url,
            "redirect_chain": report.redirect_chain,
            "is_reachable":   url.is_reachable if url else None,
        } if url else None,

        # ── Decode info ────────────────────────────────────────────────
        "decode": {
            "status":       decode.status.value if decode else None,
            "qr_count":     decode.qr_count if decode else 0,
            "image_size":   (
                f"{decode.image_width}×{decode.image_height}"
                if decode and decode.image_width else None
            ),
            "warnings":     decode.warnings if decode else [],
        },

        # ── Context info ───────────────────────────────────────────────
        "context": {
            "enriched_country": ctx.enriched_country if ctx else None,
            "is_vpn":           ctx.is_vpn if ctx else None,
            "is_tor":           ctx.is_tor if ctx else None,
        } if ctx else None,

        # ── Deception info ─────────────────────────────────────────────
        "deception": _deception_to_dict(report.deception_result),

        # ── Meta ───────────────────────────────────────────────────────
        "analysed_at": report.analysed_at,
    }


def _deception_to_dict(d: Optional[DeceptionResult]) -> Optional[Dict[str, Any]]:
    """Serialise DeceptionResult to a JSON-safe dict."""
    if d is None:
        return None
    mi = d.message_intent
    return {
        "is_deceptive":    d.is_deceptive,
        "deception_types": [dt.value for dt in d.deception_types],
        "summary":         d.summary,
        "qr_action":       d.qr_action.value,
        "qr_amount":       d.qr_amount,
        "qr_vpa":          d.qr_vpa,
        "message_intent":  {
            "raw_message":    mi.raw_message,
            "intent":         mi.intent.value,
            "primary_amount": mi.primary_amount,
            "purpose":        mi.purpose,
            "urgency":        mi.urgency,
            "authority_claim": mi.authority_claim,
            "confidence":     round(mi.confidence, 2),
        } if mi else None,
        "findings": [
            {
                "rule":        f.rule,
                "severity":    f.severity.value,
                "description": f.description,
                "evidence":    f.evidence,
            }
            for f in d.findings
        ],
    }


def _safe_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Remove or redact fields that should not be serialised (e.g. raw password)."""
    REDACT = {"password", "all_params"}
    return {
        k: ("***REDACTED***" if k in REDACT else v)
        for k, v in fields.items()
        if isinstance(v, (str, int, float, bool, list, type(None)))
    }
