import httpx
from app.tools.base_tool import ThreatIntelTool


# DEPRECATED: the ThreatCrowd service is offline (DNS no longer resolves).
# The tool is kept for reference but is not wired into any agent and is
# seeded as inactive in api_configs.
class ThreatCrowdTool(ThreatIntelTool):
    name: str = "threatcrowd"
    description: str = "Get relationship graphs for IPs, domains, and hashes from ThreatCrowd"
    api_name: str = "threatcrowd"
    api_key_env: str = ""
    base_url: str = "https://www.threatcrowd.org/searchApi/v2"

    async def _call_api(self, ioc_value: str, ioc_type: str = "ip", **kwargs) -> dict:
        endpoint_map = {
            "ip": f"{self.base_url}/ip/report/",
            "domain": f"{self.base_url}/domain/report/",
            "hash": f"{self.base_url}/file/report/",
            "email": f"{self.base_url}/email/report/",
        }
        url = endpoint_map.get(ioc_type, f"{self.base_url}/ip/report/")
        param_map = {"ip": "ip", "domain": "domain", "hash": "resource", "email": "email"}
        param = param_map.get(ioc_type, "ip")
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, params={param: ioc_value}, timeout=15)
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        return {
            "source": "threatcrowd",
            "response_code": raw.get("response_code", "0"),
            "votes": raw.get("votes", 0),
            "resolutions": raw.get("resolutions", [])[:10],
            "hashes": raw.get("hashes", [])[:10],
            "domains": raw.get("domains", [])[:10],
            "emails": raw.get("emails", [])[:10],
            "references": raw.get("references", [])[:5],
        }
