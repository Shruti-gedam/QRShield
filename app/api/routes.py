"""
QRShield – API Routes
All REST endpoints are registered here and mounted by main.py.

Endpoints:
  POST /api/scan/upload   – multipart image upload
  POST /api/scan/base64   – base64-encoded image in JSON body
  POST /api/scan/payload  – pre-decoded QR string in JSON body
  GET  /api/health        – service health check
  GET  /api/info          – framework metadata
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse

from app.api.schemas import (
    ContextInput,
    ErrorResponse,
    HealthResponse,
    ScanImageRequest,
    ScanPayloadRequest,
    ScanResponse,
)
from app.core.pipeline import run_pipeline

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Helpers ───────────────────────────────────────────────────────────────────

_ALLOWED_MIME = {
    "image/jpeg", "image/jpg", "image/png",
    "image/webp", "image/bmp", "image/gif",
}
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


def _client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _user_agent(request: Request) -> Optional[str]:
    return request.headers.get("User-Agent")


# ── Scan: multipart image upload ──────────────────────────────────────────────

@router.post(
    "/scan/upload",
    summary="Scan QR code from uploaded image file",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["Scan"],
)
async def scan_upload(
    request: Request,
    file: UploadFile = File(..., description="QR code image (JPEG/PNG/WebP/BMP)"),
    context_json: Optional[str] = Form(
        default=None,
        description="Optional JSON string matching the ContextInput schema.",
    ),
    message: Optional[str] = Form(
        default=None,
        description="Optional free-text message/instruction that accompanied the QR code.",
    ),
):
    """
    Upload a QR code image and receive a full fraud-risk analysis report.

    The image is decoded server-side; no client-side QR library needed.
    Optionally supply scan context (timestamp, geolocation, device info, etc.)
    as a JSON-serialised `ContextInput` in the `context_json` form field.
    """
    # Validate MIME type
    content_type = (file.content_type or "").split(";")[0].strip()
    if content_type not in _ALLOWED_MIME:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{content_type}'. "
                   f"Allowed: {', '.join(sorted(_ALLOWED_MIME))}",
        )

    image_bytes = await file.read()
    if len(image_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large ({len(image_bytes):,} bytes). Max: {_MAX_UPLOAD_BYTES:,} bytes.",
        )
    if len(image_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # Parse optional context
    ctx: Optional[ContextInput] = None
    if context_json:
        try:
            import json as _json
            ctx = ContextInput.model_validate(_json.loads(context_json))
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid context_json: {exc}",
            )

    try:
        result = await run_pipeline(
            image_bytes=image_bytes,
            message=message,
            ctx_input=ctx,
            client_ip=_client_ip(request),
            user_agent=_user_agent(request),
        )
        return JSONResponse(content=result)
    except Exception as exc:
        logger.exception("Pipeline error in /scan/upload")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Scan: base64 JSON body ────────────────────────────────────────────────────

@router.post(
    "/scan/base64",
    summary="Scan QR code from base64-encoded image",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["Scan"],
)
async def scan_base64(
    body: ScanImageRequest,
    request: Request,
):
    """
    Provide a base64-encoded image string and receive a full risk report.
    Accepts raw base64 or `data:image/<type>;base64,<data>` format.
    """
    try:
        result = await run_pipeline(
            image_b64=body.image_b64,
            message=body.message,
            ctx_input=body.context,
            client_ip=_client_ip(request),
            user_agent=_user_agent(request),
        )
        return JSONResponse(content=result)
    except Exception as exc:
        logger.exception("Pipeline error in /scan/base64")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Scan: pre-decoded payload ─────────────────────────────────────────────────

@router.post(
    "/scan/payload",
    summary="Analyse a pre-decoded QR payload string",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["Scan"],
)
async def scan_payload(
    body: ScanPayloadRequest,
    request: Request,
):
    """
    If you have already decoded the QR code on the client side, send the raw
    payload string here for fraud analysis — no image upload required.

    Supports UPI intent URLs, HTTPS links, payment deep-links, plain text, etc.
    """
    try:
        result = await run_pipeline(
            raw_payload=body.payload,
            message=body.message,
            ctx_input=body.context,
            client_ip=_client_ip(request),
            user_agent=_user_agent(request),
        )
        return JSONResponse(content=result)
    except Exception as exc:
        logger.exception("Pipeline error in /scan/payload")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Health check ──────────────────────────────────────────────────────────────

@router.get(
    "/health",
    summary="Service health check",
    response_model=HealthResponse,
    tags=["System"],
)
async def health_check():
    """Returns service health and dependency status."""
    checks: dict[str, str] = {}

    # Check pyzbar
    try:
        from pyzbar import pyzbar  # noqa: F401
        checks["pyzbar"] = "ok"
    except (ImportError, FileNotFoundError, OSError):
        checks["pyzbar"] = "native dll missing (OpenCV fallback active)"

    # Check OpenCV
    try:
        import cv2  # noqa: F401
        checks["opencv"] = "ok"
    except ImportError:
        checks["opencv"] = "not installed"

    # Check Pillow
    try:
        from PIL import Image  # noqa: F401
        checks["pillow"] = "ok"
    except ImportError:
        checks["pillow"] = "not installed"

    # Check tldextract
    try:
        import tldextract  # noqa: F401
        checks["tldextract"] = "ok"
    except ImportError:
        checks["tldextract"] = "not installed"

    overall = "healthy" if all(v in ("ok",) or "ok" in v for v in checks.values()) else "degraded"

    return HealthResponse(
        status=overall,
        version="1.0.0",
        checks=checks,
    )


# ── Framework info ────────────────────────────────────────────────────────────

@router.get(
    "/info",
    summary="Framework metadata",
    tags=["System"],
)
async def info():
    return {
        "name": "QRShield",
        "version": "1.0.0",
        "description": "Context-Aware AI Framework for QR-Based Payment Fraud and Deception Detection",
        "approach": "Rule-based heuristic analysis (no ML)",
        "supported_formats": [
            "UPI Intent URL (upi://)",
            "HTTPS / HTTP payment pages",
            "Payment deep-links (paytm://, phonepe://, gpay://, bhim://)",
            "Plain text / bare VPA",
            "vCard",
            "WiFi QR",
            "Geo coordinates",
            "Mailto / Tel",
        ],
        "analysis_modules": [
            "QR Decoder (pyzbar + OpenCV fallback)",
            "Payload Parser",
            "URL Analyzer (heuristics + redirect chain)",
            "Context Engine (temporal, geo, device, network, velocity)",
            "Risk Scoring Engine",
        ],
        "endpoints": {
            "POST /api/scan/upload":  "Scan QR image (multipart upload)",
            "POST /api/scan/base64":  "Scan QR image (base64 JSON)",
            "POST /api/scan/payload": "Analyse pre-decoded QR string",
            "GET  /api/health":       "Service health",
            "GET  /api/info":         "Framework info",
        },
    }
