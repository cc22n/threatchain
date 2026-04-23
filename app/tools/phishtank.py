import httpx
from app.tools.base_tool import ThreatIntelTool


class PhishTankTool(ThreatIntelTool):
    name: str = "phishtank"
    description: str = "Check if a URL is a known phishing site via PhishTank"
    api_name: str = "phishtank"
    api_key_env: str = ""
    base_url: str = "https://checkurl.phishtank.com/checkurl/"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        import urllib.parse
        data = {
            "url": urllib.parse.quote(ioc_value, safe=""),
            "format": "json",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.base_url, data=data, timeout=15)
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        result = raw.get("results", {})
        return {
            "source": "phishtank",
            "url": result.get("url", ""),
            "in_database": result.get("in_database", False),
            "phish_id": result.get("phish_id", ""),
            "phish_detail_page": result.get("phish_detail_page", ""),
            "verified": result.get("verified", False),
            "verified_at": result.get("verified_at", ""),
            "valid": result.get("valid", False),
        }
