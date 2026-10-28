"""
QRShield – Analysis Pipeline Orchestrator
Wires all core modules together into a single async call.

Flow:
  1. Decode QR (if image input)
  2. Parse payload
  3. Analyse URL (if payload is URL/UPI/deep-link)   ┐ concurrent
  4. Analyse context                                  ┘
  5. NLP deception detection (message vs QR)
  6. Compute risk score
  7. Return serialised RiskReport
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from app.api.schemas import ContextInput
from app.core.context_engine import ScanContext, analyse_context
from app.core.deception_detector import DeceptionResult, detect_deception
from app.core.payload_parser import ParsedPayload, ParseStatus, parse_payload
from app.core.qr_decoder import DecodeResult, DecodeStatus, decode_from_base64, decode_from_bytes
from app.core.risk_engine import compute_risk, report_to_dict
from app.core.url_analyzer import URLAnalysisResult, analyse_url

logger = logging.getLogger(__name__)

# Payload types that warrant URL analysis
_URL_LIKE_FORMATS = {"url", "upi", "deep_link"}


def _build_scan_context(
    ctx_input: Optional[ContextInput],
    client_ip: Optional[str],
    user_agent: Optional[str],
) -> ScanContext:
    """Map the API ContextInput DTO to the engine's ScanContext dataclass."""
    c = ctx_input or ContextInput()
    return ScanContext(
        scan_timestamp=c.scan_timestamp or datetime.now(timezone.utc),
        client_ip=client_ip,
        is_wifi=c.is_wifi,
        wifi_ssid=c.wifi_ssid,
        country_code=c.country_code,
        merchant_country=c.merchant_country,
        device_type=c.device_type,
        user_agent=user_agent,
        scans_last_minute=c.scans_last_minute,
        scans_last_hour=c.scans_last_hour,
        same_payload_count=c.same_payload_count,
        declared_amount=c.declared_amount,
    )


async def _analyse_url_if_needed(
    raw_payload: str,
    payload_format: str,
) -> Optional[URLAnalysisResult]:
    """
    Run URL analysis when the payload format is URL-like.
    For UPI / deep-links we analyse any embedded 'url' param or the raw string.
    """
    if payload_format not in _URL_LIKE_FORMATS:
        return None

    if payload_format == "url":
        target_url = raw_payload
    elif payload_format == "upi":
        from urllib.parse import parse_qs, urlparse
        try:
            params = parse_qs(urlparse(raw_payload).query)
            embedded = params.get("url", [None])[0]
            target_url = embedded or raw_payload
        except Exception:
            target_url = raw_payload
    else:
        target_url = raw_payload

    try:
        return await analyse_url(target_url)
    except Exception as exc:
        logger.error("URL analysis failed: %s", exc)
        return None


async def run_pipeline(
    *,
    image_bytes: Optional[bytes] = None,
    image_b64:   Optional[str]   = None,
    raw_payload: Optional[str]   = None,
    message:     Optional[str]   = None,   # ← NEW: accompanying free-text message
    ctx_input:   Optional[ContextInput] = None,
    client_ip:   Optional[str]   = None,
    user_agent:  Optional[str]   = None,
) -> dict:
    """
    Main entry point for the full analysis pipeline.

    Accepts either an image (bytes / base64) or a pre-decoded payload string,
    plus an optional free-text `message` that triggered / accompanied the scan.

    Returns a JSON-serialisable dict (from report_to_dict).
    """

    # ── Step 1: Decode image → payload ────────────────────────────────────
    if raw_payload:
        decode = DecodeResult(
            status=DecodeStatus.SUCCESS,
            raw_payload=raw_payload,
            payload_type=None,
            qr_count=1,
        )
    elif image_bytes:
        decode = decode_from_bytes(image_bytes)
    elif image_b64:
        decode = decode_from_base64(image_b64)
    else:
        raise ValueError(
            "One of image_bytes, image_b64, or raw_payload must be supplied."
        )

    if decode.status == DecodeStatus.FAILED:
        empty_parsed = ParsedPayload(
            format="unknown",
            status=ParseStatus.MALFORMED,
            error=decode.error or "QR decode failed.",
        )
        report = compute_risk(decode, empty_parsed, None, None, None)
        return report_to_dict(report)

    # ── Step 2: Parse payload ─────────────────────────────────────────────
    payload_str = decode.raw_payload or ""
    parsed = parse_payload(payload_str)

    # ── Steps 3 & 4: URL analysis + context scan (concurrent) ────────────
    scan_ctx = _build_scan_context(ctx_input, client_ip, user_agent)
    url_result, ctx_result = await asyncio.gather(
        _analyse_url_if_needed(payload_str, parsed.format),
        analyse_context(scan_ctx),
    )

    # ── Step 5: NLP deception detection ──────────────────────────────────
    deception_result: DeceptionResult = detect_deception(message, parsed)

    # ── Step 6: Compute risk ──────────────────────────────────────────────
    report = compute_risk(decode, parsed, url_result, ctx_result, deception_result)

    # ── Step 7: Serialise ─────────────────────────────────────────────────
    return report_to_dict(report)
