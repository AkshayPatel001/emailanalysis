"""
Analysis API endpoints.
Handles email upload, parsing, and full analysis orchestration.
"""
import logging
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import get_db
from app.models import AnalysisCase, AnalysisResult
from app.schemas import (
    AnalysisResponse, AnalyzeHeadersRequest, EmailMetadata,
    CaseListItem,
)
from app.utils.validators import validate_email_upload

from app.engines.email_parser import EmailParser
from app.engines.header_analyzer import HeaderAnalyzer
from app.engines.phishing_detector import PhishingDetector
from app.engines.url_analyzer import UrlAnalyzer
from app.engines.attachment_analyzer import AttachmentAnalyzer
from app.engines.ioc_extractor import IOCExtractor
from app.engines.risk_scorer import RiskScorer
from app.engines.mitre_mapper import MitreMapper
from app.engines.yara_engine import yara_engine
from app.tasks import detonate_attachment

logger = logging.getLogger(__name__)
router = APIRouter()

# Engine instances
email_parser = EmailParser()
header_analyzer = HeaderAnalyzer()
phishing_detector = PhishingDetector()
url_analyzer = UrlAnalyzer()
attachment_analyzer = AttachmentAnalyzer()
ioc_extractor = IOCExtractor()
risk_scorer = RiskScorer()
mitre_mapper = MitreMapper()


def generate_case_number() -> str:
    """Generate a unique case number like CASE-20260625-A1B2."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:4].upper()
    return f"CASE-{date_str}-{suffix}"


def build_recommended_actions(risk_result, header_result, phishing_result, url_result, attachment_result) -> list[str]:
    """Generate recommended actions based on analysis results."""
    actions = []
    if risk_result.verdict == "malicious":
        actions.append("BLOCK sender address and domain immediately")
        actions.append("Quarantine this email across all mailboxes")
        actions.append("Check if any users clicked links or opened attachments")
        actions.append("Submit IOCs to SIEM and threat intelligence platform")
    elif risk_result.verdict == "suspicious":
        actions.append("Quarantine email pending further investigation")
        actions.append("Verify sender identity through out-of-band communication")
        actions.append("Monitor for similar emails from this sender")

    if header_result and header_result.sender_spoofing_detected:
        actions.append("Report sender spoofing to email security gateway")
    if phishing_result and phishing_result.is_likely_phishing:
        actions.append("Report as phishing to security team")
        actions.append("Send phishing awareness reminder to targeted users")
    if url_result and url_result.malicious_count > 0:
        actions.append("Block malicious URLs at web proxy/firewall")
    if attachment_result and attachment_result.suspicious_count > 0:
        actions.append("Submit suspicious attachments to malware sandbox")
        actions.append("Block attachment hashes at endpoint protection")

    if not actions:
        actions.append("No immediate action required — email appears clean")
    return actions


@router.post("/analyze/upload", response_model=AnalysisResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload and analyze an .eml or .msg file."""
    validate_email_upload(file, settings.max_upload_bytes)

    content = await file.read()
    ext = os.path.splitext(file.filename)[1].lower()

    # Parse email
    if ext == ".msg":
        metadata, attachments_raw, raw_headers = email_parser.parse_msg(content)
    else:
        metadata, attachments_raw, raw_headers = email_parser.parse_eml(content)

    return await _run_full_analysis(metadata, attachments_raw, raw_headers, db)


@router.post("/analyze/headers", response_model=AnalysisResponse)
async def analyze_headers(
    request: AnalyzeHeadersRequest,
    db: AsyncSession = Depends(get_db),
):
    """Analyze raw email headers (and optional body)."""
    metadata, attachments_raw, raw_headers = email_parser.parse_raw_headers(
        request.raw_headers, request.body_text, request.body_html,
    )
    return await _run_full_analysis(metadata, attachments_raw, raw_headers, db)


@router.get("/analyze/{case_id}", response_model=AnalysisResponse)
async def get_analysis(case_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve a completed analysis by case ID."""
    stmt = select(AnalysisCase).where(AnalysisCase.id == case_id).options(selectinload(AnalysisCase.result))
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if not case.result:
        raise HTTPException(status_code=404, detail="Analysis result not found")

    r = case.result
    return AnalysisResponse(
        case_id=case.id, case_number=case.case_number,
        status=case.status, verdict=case.verdict,
        severity=case.severity, risk_score=case.risk_score,
        email_metadata=r.email_metadata, header_analysis=r.header_analysis,
        phishing_analysis=r.phishing_analysis, url_analysis=r.url_analysis,
        attachment_analysis=r.attachment_analysis, ioc_summary=r.ioc_summary,
        yara_analysis=r.yara_analysis,
        risk_scoring=r.risk_scoring, mitre_mappings=r.mitre_mapping,
        recommended_actions=r.recommended_actions,
        created_at=case.created_at, updated_at=case.updated_at,
    )


@router.get("/analyze/history", response_model=list[CaseListItem])
async def analysis_history(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """List recent analyses."""
    stmt = select(AnalysisCase).order_by(AnalysisCase.created_at.desc()).limit(limit)
    result = await db.execute(stmt)
    cases = result.scalars().all()
    return [
        CaseListItem(
            id=c.id, case_number=c.case_number, status=c.status,
            severity=c.severity, verdict=c.verdict, risk_score=c.risk_score,
            email_subject=c.email_subject, email_sender=c.email_sender,
            analyst_notes=c.analyst_notes,
            created_at=c.created_at, updated_at=c.updated_at,
        )
        for c in cases
    ]


async def _run_full_analysis(metadata, attachments_raw, raw_headers, db):
    """Orchestrate all analysis engines and persist results."""
    case_number = generate_case_number()
    logger.info(f"Starting analysis: {case_number}")

    # 1. Header analysis
    header_result = header_analyzer.analyze(
        raw_headers, metadata.sender_email, metadata.return_path, metadata.reply_to,
    )

    # 2. Phishing detection
    phishing_result = phishing_detector.analyze(
        metadata.subject, metadata.body_text, metadata.body_html,
        metadata.sender_email, metadata.sender_name,
    )

    # 3. URL analysis
    url_result = url_analyzer.analyze(metadata.body_text, metadata.body_html)

    # 4. Attachment analysis
    attachment_result = attachment_analyzer.analyze(attachments_raw)

    # 5. IOC extraction
    attachment_hashes = [
        {"filename": a.filename, "md5": a.md5, "sha1": a.sha1, "sha256": a.sha256}
        for a in attachments_raw
    ]
    raw_headers_text = "\n".join(f"{k}: {v}" for k, v in raw_headers.items()) if raw_headers else ""
    ioc_summary = ioc_extractor.extract(
        metadata.body_text, metadata.body_html, raw_headers_text, attachment_hashes,
    )

    # Yara Engine Scan
    yara_result = yara_engine.analyze_email(metadata.body_text, metadata.body_html, attachments_raw)

    # 6. Risk scoring
    risk_result = risk_scorer.score(header_result, phishing_result, url_result, attachment_result, yara_result)

    # 7. MITRE ATT&CK mapping
    mitre_mappings = mitre_mapper.map(header_result, phishing_result, url_result, attachment_result)

    # 8. Recommended actions
    recommended_actions = build_recommended_actions(
        risk_result, header_result, phishing_result, url_result, attachment_result,
    )

    # Persist to database
    case = AnalysisCase(
        case_number=case_number, status="completed",
        severity=risk_result.severity, verdict=risk_result.verdict,
        risk_score=risk_result.overall_score,
        email_subject=metadata.subject, email_sender=metadata.sender,
        email_recipient=metadata.recipient, email_date=None,
        email_message_id=metadata.message_id,
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(case)
    await db.flush()

    analysis_result = AnalysisResult(
        case_id=case.id,
        email_metadata=metadata.model_dump(),
        raw_headers=raw_headers_text,
        header_analysis=header_result.model_dump(),
        phishing_analysis=phishing_result.model_dump(),
        url_analysis=url_result.model_dump(),
        attachment_analysis=attachment_result.model_dump(),
        ioc_summary=ioc_summary.model_dump(),
        yara_analysis=yara_result.model_dump() if yara_result else None,
        risk_scoring=risk_result.model_dump(),
        mitre_mapping=[m.model_dump() for m in mitre_mappings],
        recommended_actions=recommended_actions,
    )
    db.add(analysis_result)

    logger.info(f"Analysis complete: {case_number} — Verdict: {risk_result.verdict} ({risk_result.overall_score})")

    # 9. Trigger Sandbox Detonation for suspicious attachments
    for att in attachment_result.attachments:
        if att.is_suspicious or att.risk_level in ["high", "critical"]:
            # Find the raw bytes
            att_raw = next((a.content for a in attachments_raw if a.filename == att.filename), None)
            if att_raw:
                detonate_attachment.delay(str(case.id), att_raw, att.filename)
                logger.info(f"Queued sandbox detonation for {att.filename}")

    return AnalysisResponse(
        case_id=case.id, case_number=case_number,
        status="completed", verdict=risk_result.verdict,
        severity=risk_result.severity, risk_score=risk_result.overall_score,
        email_metadata=metadata, header_analysis=header_result,
        phishing_analysis=phishing_result, url_analysis=url_result,
        attachment_analysis=attachment_result, ioc_summary=ioc_summary,
        yara_analysis=yara_result.model_dump() if yara_result else None,
        risk_scoring=risk_result, mitre_mappings=mitre_mappings,
        recommended_actions=recommended_actions,
        created_at=case.created_at, updated_at=case.updated_at,
    )
