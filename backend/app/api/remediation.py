"""
API Endpoints for SOAR Remediation.
Triggers M365 email purges.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime
import logging

from app.database import get_db
from app.models import RemediationAction, AnalysisCase
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

class RemediationRequest(BaseModel):
    action_type: str = "delete"

class RemediationResponse(BaseModel):
    id: UUID
    case_id: UUID
    action_type: str
    status: str
    affected_mailboxes: int
    log: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/{case_id}", response_model=RemediationResponse)
async def trigger_remediation(case_id: UUID, req: RemediationRequest, db: AsyncSession = Depends(get_db)):
    """Trigger a remediation action (e.g. purge email from M365) for a given case."""
    
    # Verify case exists
    stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Create remediation record
    action = RemediationAction(
        case_id=case_id,
        action_type=req.action_type,
        status="queued"
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)

    # Try to dispatch Celery task (non-blocking — if Redis is down, just log it)
    try:
        from app.tasks import purge_malicious_email
        purge_malicious_email.delay(
            str(action.id),
            str(case_id),
            settings.m365_tenant_id or "missing_tenant",
            settings.m365_client_id or "missing_client",
            settings.m365_client_secret or "missing_secret"
        )
        action.status = "in_progress"
        await db.commit()
        await db.refresh(action)
        logger.info(f"Remediation task dispatched for case {case_id}")
    except Exception as e:
        logger.warning(f"Could not dispatch Celery task (Redis may be down): {e}")
        action.status = "queued"
        action.log = f"Task queued locally. Celery/Redis not available: {str(e)[:200]}"
        await db.commit()
        await db.refresh(action)

    return action


@router.get("/{case_id}", response_model=list[RemediationResponse])
async def get_remediations(case_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get all remediation actions for a case."""
    stmt = select(RemediationAction).where(RemediationAction.case_id == case_id).order_by(RemediationAction.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()

