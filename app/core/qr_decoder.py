"""
QRShield – QR Decoder Module
Handles image ingestion (file upload / base64 / URL) and payload extraction.

Supported input types:
  - Uploaded image file (bytes)
  - Base64-encoded image string
  - PIL Image object
  - File path (str / Path)

Returns a structured DecodeResult with raw payload, payload type hint,
image metadata, and any decode warnings.
"""

from __future__ import annotations

import base64
import io
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────────

class DecodeStatus(str, Enum):
    SUCCESS = "success"
    FAILED  = "failed"
    PARTIAL = "partial"          # decoded but payload looks truncated / binary


class PayloadTypeHint(str, Enum):
    URL        = "url"           # starts with http:// or https://
    UPI        = "upi"           # upi:// scheme
    DEEP_LINK  = "deep_link"     # custom app scheme (e.g. paytm://, phonepe://)
    TEXT       = "text"          # plain text
    VCARD      = "vcard"         # BEGIN:VCARD
    WIFI       = "wifi"          # WIFI:S:...
    GEO        = "geo"           # geo: coordinates
    MAILTO     = "mailto"        # email link
    TEL        = "tel"           # phone number link
    UNKNOWN    = "unknown"


# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class DecodeResult:
    status: DecodeStatus
    raw_payload: Optional[str] = None
    payload_type: PayloadTypeHint = PayloadTypeHint.UNKNOWN
    image_width: Optional[int] = None
    image_height: Optional[int] = None
    qr_count: int = 0                    # number of QR codes found in the image
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None


# ── Internal helpers ───────────────────────────────────────────────────────────

def _classify_payload(raw: str) -> PayloadTypeHint:
    """Infer the type of a decoded QR payload from its prefix / structure."""
    lower = raw.strip().lower()

    if lower.startswith("http://") or lower.startswith("https://"):
        return PayloadTypeHint.URL
    if lower.startswith("upi://"):
        return PayloadTypeHint.UPI
    if lower.startswith("mailto:"):
        return PayloadTypeHint.MAILTO
    if lower.startswith("tel:"):
        return PayloadTypeHint.TEL
    if lower.startswith("geo:"):
        return PayloadTypeHint.GEO
    if lower.startswith("wifi:"):
        return PayloadTypeHint.WIFI
    if lower.startswith("begin:vcard"):
        return PayloadTypeHint.VCARD

    # Common payment deep-links
    PAYMENT_SCHEMES = (
        "paytm://", "phonepe://", "gpay://", "bhim://",
        "amazonpay://", "mobikwik://", "freecharge://",
    )
    if any(lower.startswith(s) for s in PAYMENT_SCHEMES):
        return PayloadTypeHint.DEEP_LINK

    return PayloadTypeHint.TEXT


def _check_payload_warnings(raw: str) -> List[str]:
    """Run basic sanity checks on the raw payload and return warning strings."""
    warnings: List[str] = []

    if len(raw) == 0:
        warnings.append("Empty payload decoded from QR code.")
        return warnings

    if len(raw) > 4296:
        warnings.append(
            f"Payload length ({len(raw)}) exceeds QR v40 max capacity. "
            "Data may be truncated or this is not a standard QR code."
        )

    # Check for null bytes / non-printable characters that indicate binary data
    non_printable = sum(1 for c in raw if ord(c) < 32 and c not in "\r\n\t")
    if non_printable > 0:
        warnings.append(
            f"Payload contains {non_printable} non-printable character(s). "
            "May be binary or obfuscated data."
        )

    # Look for embedded URL inside a non-URL payload (URL hiding)
    if not raw.lower().startswith(("http://", "https://")):
        import re
        hidden = re.findall(r"https?://\S+", raw, re.IGNORECASE)
        if hidden:
            warnings.append(
                f"Hidden URL(s) detected inside non-URL payload: {hidden}"
            )

    return warnings


def _open_image_bytes(data: bytes):
    """Open image bytes with Pillow; return PIL.Image or raise."""
    from PIL import Image
    return Image.open(io.BytesIO(data)).convert("RGB")


# ── Public API ─────────────────────────────────────────────────────────────────

def decode_from_bytes(image_bytes: bytes) -> DecodeResult:
    """Decode QR code from raw image bytes (e.g. uploaded file content)."""
    try:
        from PIL import Image
        img = _open_image_bytes(image_bytes)
        return _decode_pil_image(img)
    except Exception as exc:
        logger.error("decode_from_bytes failed: %s", exc)
        return DecodeResult(
            status=DecodeStatus.FAILED,
            error=str(exc),
        )


def decode_from_base64(b64_string: str) -> DecodeResult:
    """Decode QR code from a base64-encoded image string."""
    try:
        # Strip data-URI prefix if present (e.g. "data:image/png;base64,...")
        if "," in b64_string:
            b64_string = b64_string.split(",", 1)[1]
        raw_bytes = base64.b64decode(b64_string)
        return decode_from_bytes(raw_bytes)
    except Exception as exc:
        logger.error("decode_from_base64 failed: %s", exc)
        return DecodeResult(
            status=DecodeStatus.FAILED,
            error=f"Base64 decode error: {exc}",
        )


def decode_from_path(image_path: str | Path) -> DecodeResult:
    """Decode QR code from an image file on disk."""
    try:
        path = Path(image_path)
        if not path.exists():
            return DecodeResult(
                status=DecodeStatus.FAILED,
                error=f"File not found: {image_path}",
            )
        return decode_from_bytes(path.read_bytes())
    except Exception as exc:
        logger.error("decode_from_path failed: %s", exc)
        return DecodeResult(
            status=DecodeStatus.FAILED,
            error=str(exc),
        )


def _decode_pil_image(img) -> DecodeResult:
    """
    Core decode logic.  Tries pyzbar first; falls back to OpenCV's
    QRCodeDetector if pyzbar finds nothing.
    """
    import numpy as np

    width, height = img.size
    img_array = np.array(img)

    payloads: List[str] = []

    # ── Strategy 1: pyzbar ────────────────────────────────────────────────
    try:
        from pyzbar import pyzbar
        barcodes = pyzbar.decode(img)
        for bc in barcodes:
            if bc.type in ("QRCODE", "MICROQR"):
                data = bc.data.decode("utf-8", errors="replace")
                payloads.append(data)
    except (ImportError, FileNotFoundError, OSError):
        logger.warning("pyzbar native library unavailable – skipping pyzbar decode strategy.")
    except Exception as exc:
        logger.warning("pyzbar decode error: %s", exc)

    # ── Strategy 2: OpenCV QRCodeDetector ────────────────────────────────
    if not payloads:
        try:
            import cv2
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            detector = cv2.QRCodeDetector()
            data, _, _ = detector.detectAndDecode(gray)
            if data:
                payloads.append(data)
        except ImportError:
            logger.warning("cv2 not installed – skipping OpenCV decode strategy.")
        except Exception as exc:
            logger.warning("OpenCV QR decode error: %s", exc)

    # ── Strategy 3: Preprocessing + retry ────────────────────────────────
    if not payloads:
        try:
            import cv2
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            # Adaptive threshold to improve low-contrast QR codes
            thresh = cv2.adaptiveThreshold(
                gray, 255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, 11, 2
            )
            detector = cv2.QRCodeDetector()
            data, _, _ = detector.detectAndDecode(thresh)
            if data:
                payloads.append(data)
        except Exception as exc:
            logger.warning("Preprocessed QR decode error: %s", exc)

    # ── Assemble result ───────────────────────────────────────────────────
    if not payloads:
        return DecodeResult(
            status=DecodeStatus.FAILED,
            image_width=width,
            image_height=height,
            qr_count=0,
            error="No QR code detected in the provided image.",
        )

    raw_payload = payloads[0]
    warnings = _check_payload_warnings(raw_payload)

    if len(payloads) > 1:
        warnings.append(
            f"Multiple QR codes detected ({len(payloads)}). "
            "Only the first is analysed."
        )

    payload_type = _classify_payload(raw_payload)

    # Mark as PARTIAL if warnings suggest truncation/binary
    status = (
        DecodeStatus.PARTIAL
        if any("truncated" in w.lower() or "non-printable" in w.lower() for w in warnings)
        else DecodeStatus.SUCCESS
    )

    return DecodeResult(
        status=status,
        raw_payload=raw_payload,
        payload_type=payload_type,
        image_width=width,
        image_height=height,
        qr_count=len(payloads),
        warnings=warnings,
    )
