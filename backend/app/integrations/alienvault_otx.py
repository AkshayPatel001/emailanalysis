"""
AlienVault OTX API integration.
"""
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)


class OTXClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"

    async def check_indicator(self, ioc_type: str, value: str) -> Optional[dict]:
        """Check an indicator against OTX."""
        type_map = {
            "ip": f"indicators/IPv4/{value}/general",
            "domain": f"indicators/domain/{value}/general",
            "url": f"indicators/url/{value}/general",
            "hash_md5": f"indicators/file/{value}/general",
            "hash_sha1": f"indicators/file/{value}/general",
            "hash_sha256": f"indicators/file/{value}/general",
        }

        endpoint = type_map.get(ioc_type)
        if not endpoint:
            return None

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/{endpoint}",
                headers={"X-OTX-API-KEY": self.api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name"),
                    "validation": data.get("validation", []),
                    "type": data.get("type"),
                    "indicator": data.get("indicator"),
                }
            logger.warning(f"OTX check failed: {resp.status_code}")
            return None
