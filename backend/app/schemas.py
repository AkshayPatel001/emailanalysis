"""
Pydantic schemas for API request/response validation.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ============================================================
# Email Metadata
# ============================================================

class EmailMetadata(BaseModel):
    """Parsed email metadata."""
    sender: Optional[str] = None
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    recipient: Optional[str] = None
    cc: Optional[list[str]] = None
    bcc: Optional[list[str]] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    mime_version: Optional[str] = None
    content_type: Optional[str] = None
    x_mailer: Optional[str] = None
    received_headers: Optional[list[str]] = None
    all_headers: Optional[dict[str, str]] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    has_attachments: bool = False
    attachment_count: int = 0


# ============================================================
# Header Analysis
# ============================================================

class AuthResult(BaseModel):
    """Single authentication result (SPF/DKIM/DMARC)."""
    mechanism: str  # spf, dkim, dmarc
    result: str     # pass, fail, softfail, neutral, none, temperror, permerror
    detail: Optional[str] = None
    is_pass: bool = False


class HeaderFinding(BaseModel):
    """A single header analysis finding."""
    category: str       # authentication, spoofing, anomaly
    title: str
    description: str
    severity: str       # critical, high, medium, low, info
    risk_points: int = 0


class HeaderAnalysisResult(BaseModel):
    """Complete header analysis output."""
    spf: Optional[AuthResult] = None
    dkim: Optional[AuthResult] = None
    dmarc: Optional[AuthResult] = None
    arc: Optional[AuthResult] = None
    findings: list[HeaderFinding] = []
    sender_spoofing_detected: bool = False
    total_risk_points: int = 0


# ============================================================
# Phishing Detection
# ============================================================

class PhishingIndicator(BaseModel):
    """A detected phishing indicator."""
    category: str           # urgency, credential_harvest, bec, brand_impersonation, etc.
    indicator: str          # what was detected
    evidence: str           # the actual text/element matched
    confidence: float       # 0.0 - 1.0
    severity: str           # critical, high, medium, low
    explanation: str        # why this is suspicious


class PhishingAnalysisResult(BaseModel):
    """Complete phishing analysis output."""
    indicators: list[PhishingIndicator] = []
    overall_confidence: float = 0.0
    is_likely_phishing: bool = False
    total_risk_points: int = 0


# ============================================================
# URL Analysis
# ============================================================

class UrlFinding(BaseModel):
    """Analysis result for a single URL."""
    url: str
    domain: str
    is_https: bool = False
    is_shortened: bool = False
    is_punycode: bool = False
    is_typosquat: bool = False
    typosquat_target: Optional[str] = None
    suspicious_tld: bool = False
    tld: Optional[str] = None
    redirect_chain: Optional[list[str]] = None
    reputation: str = "unknown"       # clean, suspicious, malicious, unknown
    risk_level: str = "unknown"       # safe, low, medium, high, critical
    risk_points: int = 0
    enrichment: Optional[dict] = None  # VT/URLScan results


class UrlAnalysisResult(BaseModel):
    """Complete URL analysis output."""
    urls_found: int = 0
    urls: list[UrlFinding] = []
    malicious_count: int = 0
    suspicious_count: int = 0
    total_risk_points: int = 0


# ============================================================
# Attachment Analysis
# ============================================================

class AttachmentFinding(BaseModel):
    """Analysis result for a single attachment."""
    filename: str
    file_size: int
    file_size_human: str
    mime_type: Optional[str] = None
    extension: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    is_executable: bool = False
    is_script: bool = False
    is_archive: bool = False
    is_macro_enabled: bool = False
    has_double_extension: bool = False
    is_suspicious: bool = False
    risk_level: str = "safe"
    risk_points: int = 0
    findings: list[str] = []
    enrichment: Optional[dict] = None


class AttachmentAnalysisResult(BaseModel):
    """Complete attachment analysis output."""
    attachment_count: int = 0
    attachments: list[AttachmentFinding] = []
    suspicious_count: int = 0
    total_risk_points: int = 0


# ============================================================
# IOC Extraction
# ============================================================

class IOCItem(BaseModel):
    """A single extracted IOC."""
    ioc_type: str       # ip, domain, url, hash_md5, hash_sha1, hash_sha256, email
    value: str
    defanged: str
    context: Optional[str] = None
    reputation: Optional[str] = None
    enrichment: Optional[dict] = None


class IOCSummary(BaseModel):
    """Complete IOC extraction output."""
    total_count: int = 0
    ips: list[IOCItem] = []
    domains: list[IOCItem] = []
    urls: list[IOCItem] = []
    hashes: list[IOCItem] = []
    emails: list[IOCItem] = []


# ============================================================
# Risk Scoring
# ============================================================

class RiskBreakdown(BaseModel):
    """Breakdown of risk score by category."""
    category: str
    points: int
    max_points: int
    description: str


class RiskScoringResult(BaseModel):
    """Complete risk scoring output."""
    overall_score: float = 0.0      # 0-100
    verdict: str = "clean"          # clean, suspicious, malicious
    severity: str = "safe"          # safe, low, medium, high, critical
    breakdown: list[RiskBreakdown] = []


# ============================================================
# MITRE ATT&CK
# ============================================================

class MitreMapping(BaseModel):
    """A mapped MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: float
    evidence: Optional[str] = None


# ============================================================
# Full Analysis Response
# ============================================================

class AnalysisResponse(BaseModel):
    """Complete analysis response returned to the frontend."""
    case_id: UUID
    case_number: str
    status: str
    verdict: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None

    email_metadata: Optional[EmailMetadata] = None
    header_analysis: Optional[HeaderAnalysisResult] = None
    phishing_analysis: Optional[PhishingAnalysisResult] = None
    url_analysis: Optional[UrlAnalysisResult] = None
    attachment_analysis: Optional[AttachmentAnalysisResult] = None
    ioc_summary: Optional[IOCSummary] = None
    risk_scoring: Optional[RiskScoringResult] = None
    mitre_mappings: Optional[list[MitreMapping]] = None
    yara_analysis: Optional[dict] = None
    recommended_actions: Optional[list[str]] = None

    created_at: datetime
    updated_at: datetime


# ============================================================
# Case Management
# ============================================================

class CaseListItem(BaseModel):
    """Lightweight case for list views."""
    id: UUID
    case_number: str
    status: str
    severity: Optional[str] = None
    verdict: Optional[str] = None
    risk_score: Optional[float] = None
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    analyst_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CaseUpdate(BaseModel):
    """Schema for updating a case."""
    status: Optional[str] = None
    severity: Optional[str] = None
    analyst_notes: Optional[str] = None
    assigned_analyst: Optional[str] = None


# ============================================================
# Report
# ============================================================

class ReportRequest(BaseModel):
    """Request to generate a report."""
    case_id: UUID
    format: str = "pdf"  # pdf, json, csv
    analyst_name: Optional[str] = None
    analyst_notes: Optional[str] = None


# ============================================================
# Settings
# ============================================================

class APIKeyStatus(BaseModel):
    """Status of a single API key (never exposes the key itself)."""
    service: str
    is_configured: bool
    last_used: Optional[datetime] = None


class SettingsResponse(BaseModel):
    """Current app settings (safe to expose)."""
    api_keys: list[APIKeyStatus]
    m365_config: list[APIKeyStatus]
    risk_weights: dict[str, int]
    max_upload_size_mb: int


class SettingsUpdate(BaseModel):
    """Update settings."""
    virustotal_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    alienvault_otx_api_key: Optional[str] = None
    google_safebrowsing_api_key: Optional[str] = None
    m365_tenant_id: Optional[str] = None
    m365_client_id: Optional[str] = None
    m365_client_secret: Optional[str] = None
    risk_weights: Optional[dict[str, int]] = None


# ============================================================
# Analyze Request
# ============================================================

class AnalyzeHeadersRequest(BaseModel):
    """Request to analyze raw headers."""
    raw_headers: str = Field(..., min_length=10)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
