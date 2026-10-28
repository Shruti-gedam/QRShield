"""
QRShield Application Configuration
Centralised settings loaded from environment / .env file.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List


class Settings(BaseSettings):
    # ── App ────────────────────────────────────────────────────────────────
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_debug: bool = Field(default=False, alias="APP_DEBUG")
    app_secret_key: str = Field(default="dev-secret-key", alias="APP_SECRET_KEY")

    # ── Risk thresholds ────────────────────────────────────────────────────
    risk_threshold_low: int = Field(default=30, alias="RISK_THRESHOLD_LOW")
    risk_threshold_medium: int = Field(default=60, alias="RISK_THRESHOLD_MEDIUM")
    risk_threshold_high: int = Field(default=80, alias="RISK_THRESHOLD_HIGH")

    # ── External APIs (optional) ───────────────────────────────────────────
    safe_browsing_api_key: str = Field(default="", alias="SAFE_BROWSING_API_KEY")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")

    # ── Redirect chain ─────────────────────────────────────────────────────
    max_redirect_follow: int = Field(default=5, alias="MAX_REDIRECT_FOLLOW")
    redirect_timeout_seconds: int = Field(default=5, alias="REDIRECT_TIMEOUT_SECONDS")

    # ── Context toggles ────────────────────────────────────────────────────
    enable_geo_context: bool = Field(default=True, alias="ENABLE_GEO_CONTEXT")
    enable_time_context: bool = Field(default=True, alias="ENABLE_TIME_CONTEXT")
    enable_device_context: bool = Field(default=True, alias="ENABLE_DEVICE_CONTEXT")

    # ── CORS ───────────────────────────────────────────────────────────────
    cors_origins: str = Field(
        default="http://localhost:8000", alias="CORS_ORIGINS"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    model_config = {"env_file": ".env", "populate_by_name": True}


settings = Settings()
