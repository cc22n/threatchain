import httpx
from app.tools.base_tool import ThreatIntelTool

# The CISA KEV catalog is a single large JSON file (~1 MB).
# Rather than fetching it on every _call_api invocation, the base class
# cache in Redis already deduplicates per-CVE lookups for 24 h.
# Additionally, we cache the full catalog in-process for the lifetime of
# the worker so that multiple CVE lookups within the same process reuse
# the downloaded data.  The catalog is re-fetched on next process restart.
_KEV_CATALOG_CACHE: dict | None = None


class CISAKEVTool(ThreatIntelTool):
    name: str = "cisa_kev"
    description: str = "Check if a CVE is in CISA Known Exploited Vulnerabilities catalog"
    api_name: str = "cisa_kev"
    api_key_env: str = ""
    base_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        global _KEV_CATALOG_CACHE
        if _KEV_CATALOG_CACHE is None:
            async with httpx.AsyncClient() as client:
                resp = await client.get(self.base_url, timeout=30)
                resp.raise_for_status()
                _KEV_CATALOG_CACHE = resp.json()

        vulns = _KEV_CATALOG_CACHE.get("vulnerabilities", [])
        match = next((v for v in vulns if v.get("cveID", "").upper() == ioc_value.upper()), None)
        return {"ioc_value": ioc_value, "match": match, "total_kev": len(vulns)}

    def _normalize(self, raw: dict) -> dict:
        match = raw.get("match")
        if not match:
            return {"source": "cisa_kev", "in_kev": False, "cve_id": raw.get("ioc_value", "")}
        return {
            "source": "cisa_kev",
            "in_kev": True,
            "cve_id": match.get("cveID", ""),
            "vendor_project": match.get("vendorProject", ""),
            "product": match.get("product", ""),
            "vulnerability_name": match.get("vulnerabilityName", ""),
            "date_added": match.get("dateAdded", ""),
            "due_date": match.get("dueDate", ""),
            "required_action": match.get("requiredAction", ""),
            "known_ransomware": match.get("knownRansomwareCampaignUse", "Unknown"),
        }
