import os
import httpx
from app.tools.base_tool import ThreatIntelTool


class NVDTool(ThreatIntelTool):
    name: str = "nvd"
    description: str = "Get CVE details and CVSS scores from NVD (NIST)"
    api_name: str = "nvd"
    api_key_env: str = "NVD_API_KEY"
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        # NVD_API_KEY is optional: public access is rate-limited but functional without it
        api_key = os.environ.get(self.api_key_env, "") if self.api_key_env else ""
        headers = {"apiKey": api_key} if api_key else {}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self.base_url,
                params={"cveId": ioc_value},
                headers=headers,
                timeout=20,
            )
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            return {"source": "nvd", "found": False, "cve_id": ""}
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV30") else {}
        cvss = cvss_v31 or cvss_v30
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        return {
            "source": "nvd",
            "found": True,
            "cve_id": cve.get("id", ""),
            "description": description,
            "cvss_score": cvss.get("baseScore", 0),
            "cvss_severity": cvss.get("baseSeverity", ""),
            "cvss_vector": cvss.get("vectorString", ""),
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }
