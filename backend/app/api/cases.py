"""
Cases API endpoints.
Case management: list, detail, update, delete.
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import AnalysisCase
from app.schemas import CaseListItem, CaseUpdate

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/cases", response_model=list[CaseListItem])
async def list_cases(
    status: str = None,
    severity: str = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List all analysis cases with optional filters."""
    stmt = select(AnalysisCase).order_by(AnalysisCase.created_at.desc())
    if status:
        stmt = stmt.where(AnalysisCase.status == status)
    if severity:
        stmt = stmt.where(AnalysisCase.severity == severity)
    stmt = stmt.offset(offset).limit(limit)

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


@router.get("/cases/{case_id}")
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    """Get full case details."""
    stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return {
        "id": str(case.id),
        "case_number": case.case_number,
        "status": case.status,
        "severity": case.severity,
        "verdict": case.verdict,
        "risk_score": case.risk_score,
        "email_subject": case.email_subject,
        "email_sender": case.email_sender,
        "email_recipient": case.email_recipient,
        "email_message_id": case.email_message_id,
        "analyst_notes": case.analyst_notes,
        "assigned_analyst": case.assigned_analyst,
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
        "completed_at": case.completed_at.isoformat() if case.completed_at else None,
    }


@router.patch("/cases/{case_id}")
async def update_case(case_id: str, update: CaseUpdate, db: AsyncSession = Depends(get_db)):
    """Update case status, severity, or analyst notes."""
    stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if update.status is not None:
        valid_statuses = {"new", "in_progress", "completed", "escalated", "closed"}
        if update.status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {valid_statuses}")
        case.status = update.status
    if update.severity is not None:
        case.severity = update.severity
    if update.analyst_notes is not None:
        case.analyst_notes = update.analyst_notes
    if update.assigned_analyst is not None:
        case.assigned_analyst = update.assigned_analyst

    case.updated_at = datetime.now(timezone.utc)
    logger.info(f"Case {case.case_number} updated", extra={"case_id": str(case.id)})

    return {"message": "Case updated", "case_number": case.case_number}


@router.delete("/cases/{case_id}")
async def delete_case(case_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a case and all associated data."""
    stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    await db.delete(case)
    logger.info(f"Case {case.case_number} deleted")
    return {"message": "Case deleted", "case_number": case.case_number}
