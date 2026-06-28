"""
Google Safe Browsing API integration.
"""
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)


class SafeBrowsingClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4"

    async def check_urls(self, urls: list[str]) -> Optional[dict]:
        """Check URLs against Google Safe Browsing."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/threatMatches:find?key={self.api_key}",
                json={
                    "client": {"clientId": "email-analysis-tool", "clientVersion": "1.0.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": u} for u in urls[:500]],
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                return {
                    "total_checked": len(urls),
                    "threats_found": len(matches),
                    "matches": [
                        {
                            "url": m.get("threat", {}).get("url"),
                            "threat_type": m.get("threatType"),
                            "platform_type": m.get("platformType"),
                        }
                        for m in matches
                    ],
                }
            logger.warning(f"Safe Browsing check failed: {resp.status_code}")
            return None
