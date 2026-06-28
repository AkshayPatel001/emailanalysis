"""
API Endpoints for YARA Rules Management.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime

from app.database import get_db
from app.models import YaraRule
from app.engines.yara_engine import yara_engine
import yara

router = APIRouter()

class YaraRuleCreate(BaseModel):
    rule_name: str
    rule_content: str
    author: str | None = None
    is_active: bool = True

class YaraRuleUpdate(BaseModel):
    rule_content: str | None = None
    is_active: bool | None = None

class YaraRuleResponse(BaseModel):
    id: UUID
    rule_name: str
    rule_content: str
    author: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.get("/", response_model=list[YaraRuleResponse])
async def list_rules(db: AsyncSession = Depends(get_db)):
    """List all custom YARA rules."""
    stmt = select(YaraRule).order_by(YaraRule.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/", response_model=YaraRuleResponse)
async def create_rule(rule: YaraRuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new YARA rule."""
    # Validate YARA syntax before saving
    try:
        yara.compile(source=rule.rule_content)
    except yara.SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"YARA Syntax Error: {str(e)}")

    db_rule = YaraRule(
        rule_name=rule.rule_name,
        rule_content=rule.rule_content,
        author=rule.author,
        is_active=rule.is_active
    )
    db.add(db_rule)
    try:
        await db.commit()
        await db.refresh(db_rule)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Rule name must be unique.")

    # Reload engine
    await yara_engine.reload_rules(db)
    
    return db_rule


@router.patch("/{rule_id}", response_model=YaraRuleResponse)
async def update_rule(rule_id: UUID, updates: YaraRuleUpdate, db: AsyncSession = Depends(get_db)):
    """Update an existing YARA rule."""
    stmt = select(YaraRule).where(YaraRule.id == rule_id)
    result = await db.execute(stmt)
    db_rule = result.scalar_one_or_none()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if updates.rule_content is not None:
        try:
            yara.compile(source=updates.rule_content)
        except yara.SyntaxError as e:
            raise HTTPException(status_code=400, detail=f"YARA Syntax Error: {str(e)}")
        db_rule.rule_content = updates.rule_content

    if updates.is_active is not None:
        db_rule.is_active = updates.is_active

    await db.commit()
    await db.refresh(db_rule)

    # Reload engine
    await yara_engine.reload_rules(db)

    return db_rule


@router.delete("/{rule_id}")
async def delete_rule(rule_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete a YARA rule."""
    stmt = select(YaraRule).where(YaraRule.id == rule_id)
    result = await db.execute(stmt)
    db_rule = result.scalar_one_or_none()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    await db.delete(db_rule)
    await db.commit()

    # Reload engine
    await yara_engine.reload_rules(db)

    return {"detail": "Rule deleted successfully"}
