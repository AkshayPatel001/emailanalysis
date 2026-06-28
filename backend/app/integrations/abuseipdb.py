"""
AbuseIPDB API integration.
"""
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)


class AbuseIPDBClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def check_ip(self, ip: str) -> Optional[dict]:
        """Check IP reputation on AbuseIPDB."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "ip_address": data.get("ipAddress"),
                    "is_public": data.get("isPublic"),
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_tor": data.get("isTor", False),
                }
            logger.warning(f"AbuseIPDB check failed: {resp.status_code}")
            return None
