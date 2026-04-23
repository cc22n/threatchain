import httpx
from app.tools.base_tool import ThreatIntelTool


class VirusTotalTool(ThreatIntelTool):
    name: str = "virustotal"
    description: str = "Check reputation of IPs, domains, hashes, and URLs via VirusTotal"
    api_name: str = "virustotal"
    api_key_env: str = "VIRUSTOTAL_API_KEY"
    base_url: str = "https://www.virustotal.com/api/v3"

    async def _call_api(self, ioc_value: str, ioc_type: str = "ip_addresses", **kwargs) -> dict:
        endpoint_map = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "url": "urls",
        }
        resource = endpoint_map.get(ioc_type, "ip_addresses")
        api_key = self._get_api_key()
        headers = {"x-apikey": api_key}

        async with httpx.AsyncClient() as client:
            if ioc_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
                resp = await client.get(f"{self.base_url}/urls/{url_id}", headers=headers, timeout=15)
            else:
                resp = await client.get(f"{self.base_url}/{resource}/{ioc_value}", headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        data = raw.get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "tags": attrs.get("tags", []),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
        }
