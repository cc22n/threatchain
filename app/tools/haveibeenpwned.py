import httpx
from app.tools.base_tool import ThreatIntelTool


class HaveIBeenPwnedTool(ThreatIntelTool):
    name: str = "haveibeenpwned"
    description: str = "Check if an email or domain has appeared in known data breaches via HIBP"
    api_name: str = "haveibeenpwned"
    api_key_env: str = "HIBP_API_KEY"
    base_url: str = "https://haveibeenpwned.com/api/v3"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        headers = {
            "hibp-api-key": self._get_api_key(),
            "user-agent": "ThreatChain-SOC-Pipeline",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/breachedaccount/{ioc_value}",
                headers=headers,
                params={"truncateResponse": False},
                timeout=15,
            )
            if resp.status_code == 404:
                return {"breaches": [], "pwned": False}
            resp.raise_for_status()
            return {"breaches": resp.json(), "pwned": True}

    def _normalize(self, raw: dict) -> dict:
        breaches = raw.get("breaches", [])
        return {
            "source": "haveibeenpwned",
            "pwned": raw.get("pwned", False),
            "breach_count": len(breaches),
            "breaches": [
                {
                    "name": b.get("Name", ""),
                    "domain": b.get("Domain", ""),
                    "breach_date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                }
                for b in breaches[:10]
            ],
        }
