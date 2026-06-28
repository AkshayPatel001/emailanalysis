"""
Settings API endpoints.
View and update API keys and risk scoring weights.
"""
import logging

from fastapi import APIRouter
from app.config import settings
from app.schemas import SettingsResponse, SettingsUpdate, APIKeyStatus

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/settings", response_model=SettingsResponse)
async def get_settings():
    """Get current settings (API keys are shown as configured/not configured)."""
    api_keys = [
        APIKeyStatus(service="VirusTotal", is_configured=bool(settings.virustotal_api_key)),
        APIKeyStatus(service="URLScan.io", is_configured=bool(settings.urlscan_api_key)),
        APIKeyStatus(service="AbuseIPDB", is_configured=bool(settings.abuseipdb_api_key)),
        APIKeyStatus(service="AlienVault OTX", is_configured=bool(settings.alienvault_otx_api_key)),
        APIKeyStatus(service="Google Safe Browsing", is_configured=bool(settings.google_safebrowsing_api_key)),
    ]

    m365_config = [
        APIKeyStatus(service="Tenant ID", is_configured=bool(settings.m365_tenant_id)),
        APIKeyStatus(service="Client ID", is_configured=bool(settings.m365_client_id)),
        APIKeyStatus(service="Client Secret", is_configured=bool(settings.m365_client_secret)),
    ]

    risk_weights = {
        "header_anomaly": settings.weight_header_anomaly,
        "auth_failure": settings.weight_auth_failure,
        "sender_spoof": settings.weight_sender_spoof,
        "suspicious_attachment": settings.weight_suspicious_attachment,
        "malicious_url": settings.weight_malicious_url,
        "phishing_keywords": settings.weight_phishing_keywords,
        "brand_impersonation": settings.weight_brand_impersonation,
        "bec_indicators": settings.weight_bec_indicators,
    }

    return SettingsResponse(
        api_keys=api_keys,
        m365_config=m365_config,
        risk_weights=risk_weights,
        max_upload_size_mb=settings.max_upload_size_mb,
    )


@router.patch("/settings")
async def update_settings(update: SettingsUpdate):
    """
    Update settings (runtime only — does not persist to .env).
    For persistent changes, update .env directly.
    """
    updated_fields = []

    if update.virustotal_api_key is not None:
        settings.virustotal_api_key = update.virustotal_api_key
        updated_fields.append("virustotal_api_key")
    if update.urlscan_api_key is not None:
        settings.urlscan_api_key = update.urlscan_api_key
        updated_fields.append("urlscan_api_key")
    if update.abuseipdb_api_key is not None:
        settings.abuseipdb_api_key = update.abuseipdb_api_key
        updated_fields.append("abuseipdb_api_key")
    if update.alienvault_otx_api_key is not None:
        settings.alienvault_otx_api_key = update.alienvault_otx_api_key
        updated_fields.append("alienvault_otx_api_key")
    if update.google_safebrowsing_api_key is not None:
        settings.google_safebrowsing_api_key = update.google_safebrowsing_api_key
        updated_fields.append("google_safebrowsing_api_key")

    if update.m365_tenant_id is not None:
        settings.m365_tenant_id = update.m365_tenant_id
        updated_fields.append("m365_tenant_id")
    if update.m365_client_id is not None:
        settings.m365_client_id = update.m365_client_id
        updated_fields.append("m365_client_id")
    if update.m365_client_secret is not None:
        settings.m365_client_secret = update.m365_client_secret
        updated_fields.append("m365_client_secret")

    if update.risk_weights:
        for key, value in update.risk_weights.items():
            attr = f"weight_{key}"
            if hasattr(settings, attr):
                setattr(settings, attr, value)
                updated_fields.append(attr)

    logger.info(f"Settings updated: {updated_fields}")
    return {"message": "Settings updated", "updated_fields": updated_fields}
