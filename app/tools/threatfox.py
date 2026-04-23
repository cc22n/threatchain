import httpx
from app.tools.base_tool import ThreatIntelTool


class ThreatFoxTool(ThreatIntelTool):
    name: str = "threatfox"
    description: str = "Search ThreatFox IOC database for malware associations"
    api_name: str = "threatfox"
    api_key_env: str = ""
    base_url: str = "https://threatfox-api.abuse.ch/api/v1"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.base_url,
                json={"query": "search_ioc", "search_term": ioc_value},
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        if raw.get("query_status") != "ok":
            return {"source": "threatfox", "found": False}
        data = raw.get("data", [])
        if not data:
            return {"source": "threatfox", "found": False}
        entry = data[0]
        return {
            "source": "threatfox",
            "found": True,
            "ioc_type": entry.get("ioc_type", ""),
            "threat_type": entry.get("threat_type", ""),
            "malware": entry.get("malware", ""),
            "malware_alias": entry.get("malware_alias", ""),
            "confidence_level": entry.get("confidence_level", 0),
            "first_seen": entry.get("first_seen", ""),
            "last_seen": entry.get("last_seen", ""),
            "tags": entry.get("tags", []),
            "total_matches": len(data),
        }
