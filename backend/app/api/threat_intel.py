"""
Threat Intelligence API endpoints.
IOC checking against external APIs and IOC export.
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.database import get_db
from app.models import AnalysisCase, AnalysisResult, IOCEntry
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


class IOCCheckRequest(BaseModel):
    ioc_type: str  # ip, domain, url, hash
    ioc_value: str


class IOCCheckResponse(BaseModel):
    ioc_type: str
    ioc_value: str
    results: dict


class IOCBulkCheckRequest(BaseModel):
    iocs: list[IOCCheckRequest]


@router.post("/ioc/check", response_model=IOCCheckResponse)
async def check_ioc(request: IOCCheckRequest):
    """Check a single IOC against configured threat intel APIs."""
    results = {}

    # VirusTotal
    if settings.virustotal_api_key:
        try:
            from app.integrations.virustotal import VirusTotalClient
            vt = VirusTotalClient(settings.virustotal_api_key)
            if request.ioc_type in ("domain", "url"):
                vt_result = await vt.check_url(request.ioc_value)
            elif request.ioc_type == "ip":
                vt_result = await vt.check_ip(request.ioc_value)
            elif request.ioc_type.startswith("hash"):
                vt_result = await vt.check_hash(request.ioc_value)
            else:
                vt_result = None
            if vt_result:
                results["virustotal"] = vt_result
        except Exception as e:
            logger.warning(f"VirusTotal check failed: {e}")
            results["virustotal"] = {"error": str(e)}

    # AbuseIPDB
    if settings.abuseipdb_api_key and request.ioc_type == "ip":
        try:
            from app.integrations.abuseipdb import AbuseIPDBClient
            ab = AbuseIPDBClient(settings.abuseipdb_api_key)
            ab_result = await ab.check_ip(request.ioc_value)
            if ab_result:
                results["abuseipdb"] = ab_result
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed: {e}")
            results["abuseipdb"] = {"error": str(e)}

    # AlienVault OTX
    if settings.alienvault_otx_api_key:
        try:
            from app.integrations.alienvault_otx import OTXClient
            otx = OTXClient(settings.alienvault_otx_api_key)
            otx_result = await otx.check_indicator(request.ioc_type, request.ioc_value)
            if otx_result:
                results["alienvault_otx"] = otx_result
        except Exception as e:
            logger.warning(f"AlienVault OTX check failed: {e}")
            results["alienvault_otx"] = {"error": str(e)}

    if not results:
        results["info"] = "No API keys configured. Add keys in Settings to enable threat intel lookups."

    return IOCCheckResponse(ioc_type=request.ioc_type, ioc_value=request.ioc_value, results=results)


@router.post("/ioc/bulk-check")
async def bulk_check_iocs(request: IOCBulkCheckRequest):
    """Check multiple IOCs against configured threat intel APIs."""
    results = []
    for ioc in request.iocs[:25]:  # Limit to 25 per batch
        result = await check_ioc(ioc)
        results.append(result)
    return {"results": results, "total_checked": len(results)}


@router.get("/ioc/export/{case_id}")
async def export_iocs(case_id: str, format: str = "csv", db: AsyncSession = Depends(get_db)):
    """Export IOCs for a case in CSV or STIX format."""
    stmt = select(AnalysisResult).where(AnalysisResult.case_id == case_id)
    result = await db.execute(stmt)
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    ioc_data = analysis.ioc_summary or {}

    if format == "csv":
        lines = ["type,value,defanged,context"]
        for category in ["ips", "domains", "urls", "hashes", "emails"]:
            for ioc in ioc_data.get(category, []):
                lines.append(f"{ioc.get('ioc_type','')},{ioc.get('value','')},{ioc.get('defanged','')},{ioc.get('context','')}")
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content="\n".join(lines), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=iocs_{case_id[:8]}.csv"})
    else:
        # Return as JSON (simplified STIX-like)
        return {
            "type": "bundle",
            "id": f"bundle--{case_id}",
            "objects": [
                {"type": "indicator", "pattern_type": "stix",
                 "indicator_type": ioc.get("ioc_type"), "value": ioc.get("value")}
                for category in ["ips", "domains", "urls", "hashes", "emails"]
                for ioc in ioc_data.get(category, [])
            ]
        }
