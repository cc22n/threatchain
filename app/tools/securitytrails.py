import httpx
from app.tools.base_tool import ThreatIntelTool


class SecurityTrailsTool(ThreatIntelTool):
    name: str = "securitytrails"
    description: str = "Get historical DNS records and subdomains via SecurityTrails"
    api_name: str = "securitytrails"
    api_key_env: str = "SECURITYTRAILS_API_KEY"
    base_url: str = "https://api.securitytrails.com/v1"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        headers = {"APIKEY": self._get_api_key()}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/domain/{ioc_value}",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        current_dns = raw.get("current_dns", {})
        a_records = current_dns.get("a", {}).get("values", [])
        mx_records = current_dns.get("mx", {}).get("values", [])
        return {
            "source": "securitytrails",
            "hostname": raw.get("hostname", ""),
            "a_records": [r.get("ip", "") for r in a_records],
            "mx_records": [r.get("hostname", "") for r in mx_records],
            "alexa_rank": raw.get("alexa_rank", 0),
            "whois_registrar": raw.get("whois", {}).get("registrar", ""),
            "whois_created": raw.get("whois", {}).get("createdDate", ""),
            "whois_expires": raw.get("whois", {}).get("expiresDate", ""),
            "subdomains_count": len(raw.get("subdomains", [])),
        }
