import httpx
from app.tools.base_tool import ThreatIntelTool


class GreyNoiseTool(ThreatIntelTool):
    name: str = "greynoise"
    description: str = "Check if an IP is internet background noise or a targeted attacker via GreyNoise"
    api_name: str = "greynoise"
    api_key_env: str = "GREYNOISE_API_KEY"
    base_url: str = "https://api.greynoise.io/v3"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        headers = {"key": self._get_api_key()}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/community/{ioc_value}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 404:
                return {"ip": ioc_value, "noise": False, "riot": False, "classification": "unknown", "message": "not found"}
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        return {
            "source": "greynoise",
            "ip": raw.get("ip", ""),
            "noise": raw.get("noise", False),
            "riot": raw.get("riot", False),
            "classification": raw.get("classification", "unknown"),
            "name": raw.get("name", ""),
            "link": raw.get("link", ""),
            "last_seen": raw.get("last_seen", ""),
            "message": raw.get("message", ""),
        }
