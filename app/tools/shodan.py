import httpx
from app.tools.base_tool import ThreatIntelTool


class ShodanTool(ThreatIntelTool):
    name: str = "shodan"
    description: str = "Get open ports, services, and banners for an IP via Shodan"
    api_name: str = "shodan"
    api_key_env: str = "SHODAN_API_KEY"
    base_url: str = "https://api.shodan.io"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        api_key = self._get_api_key()
        # Shodan REST API only accepts the key as a query parameter; there is
        # no header-based auth.  This is a vendor constraint, not a local choice.
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/shodan/host/{ioc_value}",
                params={"key": api_key},
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        ports = raw.get("ports", [])
        hostnames = raw.get("hostnames", [])
        vulns = raw.get("vulns", [])
        services = []
        for item in raw.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
            })
        return {
            "source": "shodan",
            "ip": raw.get("ip_str", ""),
            "country": raw.get("country_name", ""),
            "city": raw.get("city", ""),
            "org": raw.get("org", ""),
            "isp": raw.get("isp", ""),
            "asn": raw.get("asn", ""),
            "os": raw.get("os", ""),
            "ports": ports,
            "hostnames": hostnames,
            "vulns": list(vulns) if isinstance(vulns, (list, set)) else [],
            "services": services,
            "last_update": raw.get("last_update", ""),
        }
