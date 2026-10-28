"""
QRShield – API Request / Response Schemas
Pydantic models for all REST endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Shared sub-models ─────────────────────────────────────────────────────────

class ContextInput(BaseModel):
    """Optional scan-context block that the client can supply."""
    scan_timestamp: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the scan. Defaults to server time if omitted.",
    )
    country_code: Optional[str] = Field(
        default=None,
        max_length=2,
        description="ISO-3166-1 alpha-2 country code of the scanning device.",
        examples=["IN", "US"],
    )
    merchant_country: Optional[str] = Field(
        default=None,
        max_length=2,
        description="Country where the merchant / payee is registered.",
        examples=["IN"],
    )
    is_wifi: Optional[bool] = Field(
        default=None,
        description="True if device is on a Wi-Fi network.",
    )
    wifi_ssid: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Wi-Fi SSID (for public-hotspot detection).",
    )
    device_type: Optional[str] = Field(
        default=None,
        description="'mobile' | 'desktop' | 'tablet'",
        examples=["mobile"],
    )
    scans_last_minute: int = Field(default=0, ge=0)
    scans_last_hour: int = Field(default=0, ge=0)
    same_payload_count: int = Field(default=0, ge=0)
    declared_amount: Optional[float] = Field(
        default=None,
        description="Amount shown to user in the UI before scanning.",
    )


# ── Request models ────────────────────────────────────────────────────────────

class ScanImageRequest(BaseModel):
    """
    Analyse a QR code image supplied as a base64 string.
    Use the /scan/upload endpoint for multipart file uploads instead.
    """
    image_b64: str = Field(
        description="Base64-encoded image (with or without data-URI prefix).",
    )
    message: Optional[str] = Field(
        default=None,
        max_length=2000,
        description=(
            "Optional free-text message or instruction accompanying the QR "
            "(e.g. 'Scan to receive ₹5,000 refund'). Used by the NLP "
            "deception detector to compare stated intent with actual QR action."
        ),
    )
    context: Optional[ContextInput] = None

    @field_validator("image_b64")
    @classmethod
    def validate_b64_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("image_b64 must not be empty.")
        return v


class ScanPayloadRequest(BaseModel):
    """
    Analyse a pre-decoded QR payload string directly (no image needed).
    Useful when the client has already decoded the QR code natively.
    """
    payload: str = Field(
        description="Raw decoded QR code string.",
        min_length=1,
        max_length=8192,
    )
    message: Optional[str] = Field(
        default=None,
        max_length=2000,
        description=(
            "Optional free-text message or instruction accompanying the QR. "
            "Used by the NLP deception detector."
        ),
    )
    context: Optional[ContextInput] = None


# ── Response sub-models ───────────────────────────────────────────────────────

class FindingOut(BaseModel):
    rule: str
    severity: str
    description: str
    evidence: Optional[str] = None


class SubScoresOut(BaseModel):
    payload: int
    url: int
    context: int
    decode: int
    deception: int = 0


class PayloadInfoOut(BaseModel):
    format: str
    raw: Optional[str] = None
    status: Optional[str] = None
    fields: Dict[str, Any] = Field(default_factory=dict)


class URLInfoOut(BaseModel):
    final_url: Optional[str] = None
    redirect_chain: List[str] = Field(default_factory=list)
    is_reachable: Optional[bool] = None


class DecodeInfoOut(BaseModel):
    status: Optional[str] = None
    qr_count: int = 0
    image_size: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)


class ContextInfoOut(BaseModel):
    enriched_country: Optional[str] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None


class DeceptionFindingOut(BaseModel):
    rule: str
    severity: str
    description: str
    evidence: Optional[str] = None


class MessageIntentOut(BaseModel):
    raw_message: str
    intent: str
    primary_amount: Optional[float] = None
    purpose: Optional[str] = None
    urgency: bool = False
    authority_claim: bool = False
    confidence: float = 0.0


class DeceptionOut(BaseModel):
    is_deceptive: bool
    deception_types: List[str] = Field(default_factory=list)
    summary: str
    qr_action: str
    qr_amount: Optional[float] = None
    qr_vpa: Optional[str] = None
    message_intent: Optional[MessageIntentOut] = None
    findings: List[DeceptionFindingOut] = Field(default_factory=list)


# ── Primary response model ────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """Full analysis response returned by all scan endpoints."""
    score: int = Field(description="Risk score 0–100.")
    verdict: str = Field(description="SAFE | SUSPICIOUS | HIGH_RISK | CRITICAL")
    verdict_color: str
    verdict_icon: str
    explanation: str
    recommendations: List[str]
    sub_scores: SubScoresOut
    top_findings: List[FindingOut]
    all_findings: List[FindingOut]
    payload: PayloadInfoOut
    url_analysis: Optional[URLInfoOut] = None
    decode: DecodeInfoOut
    context: Optional[ContextInfoOut] = None
    deception: Optional[DeceptionOut] = None
    analysed_at: str


class HealthResponse(BaseModel):
    status: str
    version: str
    checks: Dict[str, str]


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
