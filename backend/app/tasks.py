"""
Celery Background Tasks.
"""
import asyncio
import logging
from uuid import UUID

from app.celery_app import celery_app
from app.integrations.cuckoo import CuckooSandbox
from app.integrations.ms_graph import MSGraphClient
from app.database import async_session_factory
from app.models import AnalysisCase, AnalysisResult, RemediationAction
from sqlalchemy import select

logger = logging.getLogger(__name__)


def run_async(coro):
    """Helper to run async code in Celery sync tasks."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@celery_app.task(name="tasks.detonate_attachment")
def detonate_attachment(case_id: str, attachment_bytes: bytes, filename: str):
    """Submit an attachment to the sandbox and wait for the report."""
    logger.info(f"Starting sandbox detonation for case {case_id}")
    
    async def process():
        sandbox = CuckooSandbox()
        task_id = await sandbox.submit_file(attachment_bytes, filename)
        
        # Simulate waiting for the sandbox
        await asyncio.sleep(5) 
        
        report = await sandbox.get_report(task_id)
        
        # Update database with sandbox results
        async with async_session_factory() as session:
            stmt = select(AnalysisResult).where(AnalysisResult.case_id == case_id)
            result = await session.execute(stmt)
            analysis = result.scalar_one_or_none()
            
            if analysis:
                current_att_analysis = analysis.attachment_analysis or {}
                # Append sandbox results to the specific attachment
                for att in current_att_analysis.get('attachments', []):
                    if att['filename'] == filename:
                        att['sandbox_report'] = report
                        att['risk_level'] = 'critical' if report['score'] > 7 else 'high'
                
                analysis.attachment_analysis = current_att_analysis
                await session.commit()
                logger.info(f"Sandbox results saved for {filename}")

    run_async(process())
    return {"status": "success", "filename": filename}


@celery_app.task(name="tasks.purge_malicious_email")
def purge_malicious_email(remediation_id: str, case_id: str, tenant_id: str, client_id: str, client_secret: str):
    """Search and delete a malicious email via MS Graph API."""
    logger.info(f"Starting email purge for remediation {remediation_id}")
    
    async def process():
        async with async_session_factory() as session:
            # 1. Get the Case to find the Message-ID
            stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
            result = await session.execute(stmt)
            case = result.scalar_one_or_none()
            
            if not case or not case.email_message_id:
                logger.error("Case not found or missing Message-ID")
                return
                
            # 2. Call MS Graph
            graph = MSGraphClient(tenant_id, client_id, client_secret)
            res = await graph.search_and_delete_email(case.email_message_id)
            
            # 3. Update RemediationAction record
            stmt_rem = select(RemediationAction).where(RemediationAction.id == remediation_id)
            result_rem = await session.execute(stmt_rem)
            remediation = result_rem.scalar_one_or_none()
            
            if remediation:
                remediation.status = "completed" if res["status"] == "success" else "failed"
                remediation.affected_mailboxes = res.get("affected_mailboxes", 0)
                remediation.log = res.get("log") or res.get("error")
                await session.commit()
                
    run_async(process())
    return {"status": "success", "remediation_id": remediation_id}
