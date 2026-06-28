"""
Application configuration loaded from environment variables.
Uses pydantic-settings for type-safe config with .env file support.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Central configuration for the Email Analysis Tool."""

    # --- Application ---
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    secret_key: str = Field(default="dev-secret-key-change-in-production", alias="SECRET_KEY")
    max_upload_size_mb: int = Field(default=25, alias="MAX_UPLOAD_SIZE_MB")
    allowed_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000",
        alias="ALLOWED_ORIGINS",
    )

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://emailanalysis:changeme_secure_password@db:5432/email_analysis",
        alias="DATABASE_URL",
    )

    # --- External API Keys (all optional) ---
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    urlscan_api_key: Optional[str] = Field(default=None, alias="URLSCAN_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, alias="ABUSEIPDB_API_KEY")
    alienvault_otx_api_key: Optional[str] = Field(default=None, alias="ALIENVAULT_OTX_API_KEY")
    google_safebrowsing_api_key: Optional[str] = Field(default=None, alias="GOOGLE_SAFEBROWSING_API_KEY")

    # --- SOAR Integrations (M365) ---
    m365_tenant_id: Optional[str] = Field(default=None, alias="M365_TENANT_ID")
    m365_client_id: Optional[str] = Field(default=None, alias="M365_CLIENT_ID")
    m365_client_secret: Optional[str] = Field(default=None, alias="M365_CLIENT_SECRET")

    # --- Risk Scoring Weights ---
    weight_header_anomaly: int = Field(default=25, alias="WEIGHT_HEADER_ANOMALY")
    weight_auth_failure: int = Field(default=20, alias="WEIGHT_AUTH_FAILURE")
    weight_sender_spoof: int = Field(default=15, alias="WEIGHT_SENDER_SPOOF")
    weight_suspicious_attachment: int = Field(default=30, alias="WEIGHT_SUSPICIOUS_ATTACHMENT")
    weight_malicious_url: int = Field(default=40, alias="WEIGHT_MALICIOUS_URL")
    weight_phishing_keywords: int = Field(default=15, alias="WEIGHT_PHISHING_KEYWORDS")
    weight_brand_impersonation: int = Field(default=20, alias="WEIGHT_BRAND_IMPERSONATION")
    weight_bec_indicators: int = Field(default=25, alias="WEIGHT_BEC_INDICATORS")
    weight_yara_match: int = Field(default=50, alias="WEIGHT_YARA_MATCH")

    # --- Logging ---
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")

    @property
    def origins_list(self) -> list[str]:
        """Parse comma-separated origins into a list."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


# Singleton instance
settings = Settings()
