"""
Reports API endpoints.
Generate and download investigation reports in PDF, JSON, CSV.
"""
import io
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import AnalysisCase, AnalysisResult
from app.schemas import ReportRequest

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/reports/generate")
async def generate_report(request: ReportRequest, db: AsyncSession = Depends(get_db)):
    """Generate a report for a case."""
    stmt = select(AnalysisCase).where(AnalysisCase.id == request.case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case or not case.result:
        raise HTTPException(status_code=404, detail="Case or analysis not found")

    r = case.result

    if request.format == "json":
        report_data = _build_report_data(case, r, request.analyst_name, request.analyst_notes)
        content = json.dumps(report_data, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()), media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=report_{case.case_number}.json"},
        )

    elif request.format == "csv":
        lines = _build_csv_report(case, r)
        content = "\n".join(lines)
        return StreamingResponse(
            io.BytesIO(content.encode()), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{case.case_number}.csv"},
        )

    elif request.format == "pdf":
        try:
            from app.reports.pdf_generator import generate_pdf_report
            pdf_bytes = generate_pdf_report(case, r, request.analyst_name, request.analyst_notes)
            return StreamingResponse(
                io.BytesIO(pdf_bytes), media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=report_{case.case_number}.pdf"},
            )
        except ImportError:
            raise HTTPException(status_code=500, detail="PDF generation requires reportlab")
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use: pdf, json, csv")


@router.get("/reports")
async def list_reports(db: AsyncSession = Depends(get_db)):
    """List cases that have completed analysis (available for reports)."""
    stmt = (
        select(AnalysisCase)
        .where(AnalysisCase.status == "completed")
        .order_by(AnalysisCase.created_at.desc())
        .limit(100)
    )
    result = await db.execute(stmt)
    cases = result.scalars().all()
    return [
        {
            "case_id": str(c.id), "case_number": c.case_number,
            "verdict": c.verdict, "severity": c.severity,
            "risk_score": c.risk_score, "email_subject": c.email_subject,
            "created_at": c.created_at.isoformat(),
        }
        for c in cases
    ]


def _build_report_data(case, result, analyst_name=None, analyst_notes=None):
    """Build structured report data dict."""
    return {
        "report_metadata": {
            "case_id": str(case.id),
            "case_number": case.case_number,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analyst": analyst_name or case.assigned_analyst or "N/A",
            "analyst_notes": analyst_notes or case.analyst_notes or "",
        },
        "email_summary": {
            "subject": case.email_subject,
            "sender": case.email_sender,
            "recipient": case.email_recipient,
            "message_id": case.email_message_id,
        },
        "verdict": case.verdict,
        "severity": case.severity,
        "risk_score": case.risk_score,
        "header_analysis": result.header_analysis,
        "phishing_analysis": result.phishing_analysis,
        "url_analysis": result.url_analysis,
        "attachment_analysis": result.attachment_analysis,
        "ioc_summary": result.ioc_summary,
        "risk_scoring": result.risk_scoring,
        "mitre_mapping": result.mitre_mapping,
        "recommended_actions": result.recommended_actions,
    }


def _build_csv_report(case, result):
    """Build CSV report lines."""
    lines = [
        "Section,Field,Value",
        f"Case,Case Number,{case.case_number}",
        f"Case,Verdict,{case.verdict}",
        f"Case,Severity,{case.severity}",
        f"Case,Risk Score,{case.risk_score}",
        f"Email,Subject,\"{case.email_subject or ''}\"",
        f"Email,Sender,{case.email_sender or ''}",
        f"Email,Recipient,{case.email_recipient or ''}",
    ]

    # IOCs
    ioc_data = result.ioc_summary or {}
    for category in ["ips", "domains", "urls", "hashes", "emails"]:
        for ioc in ioc_data.get(category, []):
            lines.append(f"IOC,{ioc.get('ioc_type','')},{ioc.get('value','')}")

    # Recommended actions
    for action in (result.recommended_actions or []):
        lines.append(f"Action,Recommendation,\"{action}\"")

    return lines
