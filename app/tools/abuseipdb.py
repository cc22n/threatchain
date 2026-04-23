import httpx
from app.tools.base_tool import ThreatIntelTool


class AbuseIPDBTool(ThreatIntelTool):
    name: str = "abuseipdb"
    description: str = "Check IP reputation and abuse reports via AbuseIPDB"
    api_name: str = "abuseipdb"
    api_key_env: str = "ABUSEIPDB_API_KEY"
    base_url: str = "https://api.abuseipdb.com/api/v2"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        api_key = self._get_api_key()
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc_value, "maxAgeInDays": 90, "verbose": True}

        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/check", headers=headers, params=params, timeout=15)
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        data = raw.get("data", {})
        return {
            "source": "abuseipdb",
            "ip_address": data.get("ipAddress", ""),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
            "is_public": data.get("isPublic", True),
            "usage_type": data.get("usageType", ""),
            "last_reported_at": data.get("lastReportedAt", ""),
        }
