import httpx
from app.tools.base_tool import ThreatIntelTool


class AlienVaultOTXTool(ThreatIntelTool):
    name: str = "alienvault_otx"
    description: str = "Get threat intelligence pulses for IPs, domains, hashes, and URLs from AlienVault OTX"
    api_name: str = "alienvault_otx"
    api_key_env: str = "OTX_API_KEY"
    base_url: str = "https://otx.alienvault.com/api/v1"

    async def _call_api(self, ioc_value: str, ioc_type: str = "ip", **kwargs) -> dict:
        section_map = {
            "ip": f"indicators/IPv4/{ioc_value}/general",
            "domain": f"indicators/domain/{ioc_value}/general",
            "hash": f"indicators/file/{ioc_value}/general",
            "url": f"indicators/url/{ioc_value}/general",
        }
        path = section_map.get(ioc_type, f"indicators/IPv4/{ioc_value}/general")
        headers = {"X-OTX-API-KEY": self._get_api_key()}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/{path}", headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        return {
            "source": "alienvault_otx",
            "pulse_count": raw.get("pulse_info", {}).get("count", 0),
            "tags": raw.get("pulse_info", {}).get("tags", []),
            "malware_families": raw.get("pulse_info", {}).get("malware_families", []),
            "adversary": raw.get("pulse_info", {}).get("adversary", ""),
            "reputation": raw.get("reputation", 0),
            "country": raw.get("country_name", ""),
            "asn": raw.get("asn", ""),
        }
