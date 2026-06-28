"""
URLScan.io API integration.
"""
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)


class URLScanClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://urlscan.io/api/v1"

    async def submit_scan(self, url: str) -> Optional[dict]:
        """Submit a URL for scanning."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/scan/",
                headers={"API-Key": self.api_key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "unlisted"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return {"uuid": data.get("uuid"), "result_url": data.get("result"), "api_url": data.get("api")}
            logger.warning(f"URLScan submit failed: {resp.status_code}")
            return None

    async def get_result(self, scan_uuid: str) -> Optional[dict]:
        """Get scan result by UUID."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.base_url}/result/{scan_uuid}/")
            if resp.status_code == 200:
                data = resp.json()
                verdicts = data.get("verdicts", {}).get("overall", {})
                return {
                    "score": verdicts.get("score", 0),
                    "malicious": verdicts.get("malicious", False),
                    "categories": verdicts.get("categories", []),
                    "screenshot": data.get("task", {}).get("screenshotURL"),
                }
            return None
