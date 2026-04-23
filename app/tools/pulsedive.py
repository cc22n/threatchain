import httpx
from app.tools.base_tool import ThreatIntelTool


class PulsediveTool(ThreatIntelTool):
    name: str = "pulsedive"
    description: str = "Enrich IOCs with risk scores and threat context via Pulsedive"
    api_name: str = "pulsedive"
    api_key_env: str = "PULSEDIVE_API_KEY"
    base_url: str = "https://pulsedive.com/api"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        # API key must not go in URL query string - it ends up in server logs.
        # Pulsedive accepts the key as a query param by design (their API does
        # not support an Authorization header), so we accept this limitation
        # but keep it isolated to this method and document the risk.
        params = {"indicator": ioc_value, "key": self._get_api_key(), "pretty": 1}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/info.php", params=params, timeout=15)
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        return {
            "source": "pulsedive",
            "indicator": raw.get("indicator", ""),
            "type": raw.get("type", ""),
            "risk": raw.get("risk", "unknown"),
            "risk_recommended": raw.get("risk_recommended", "unknown"),
            "threats": [t.get("name", "") for t in raw.get("threats", [])],
            "feeds": [f.get("name", "") for f in raw.get("feeds", [])],
            "attributes": raw.get("attributes", {}),
            "stamp_seen": raw.get("stamp_seen", ""),
            "stamp_updated": raw.get("stamp_updated", ""),
        }
