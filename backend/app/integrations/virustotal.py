"""
VirusTotal API integration.
Supports URL, IP, domain, and file hash lookups.
"""
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    async def check_url(self, url: str) -> Optional[dict]:
        """Check URL reputation on VirusTotal."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=self.headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "last_analysis_date": data.get("last_analysis_date"),
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "message": "URL not in VirusTotal database"}
            else:
                logger.warning(f"VT URL check failed: {resp.status_code}")
                return None

    async def check_ip(self, ip: str) -> Optional[dict]:
        """Check IP reputation on VirusTotal."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=self.headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "country": data.get("country", "Unknown"),
                    "as_owner": data.get("as_owner", "Unknown"),
                    "reputation": data.get("reputation", 0),
                }
            return None

    async def check_hash(self, file_hash: str) -> Optional[dict]:
        """Check file hash on VirusTotal."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{VT_BASE}/files/{file_hash}", headers=self.headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "type_tag": data.get("type_tag", "Unknown"),
                    "meaningful_name": data.get("meaningful_name"),
                    "reputation": data.get("reputation", 0),
                    "popular_threat_classification": data.get("popular_threat_classification"),
                }
            elif resp.status_code == 404:
                return {"status": "not_found"}
            return None
