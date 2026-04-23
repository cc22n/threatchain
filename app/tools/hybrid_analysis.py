import httpx
from app.tools.base_tool import ThreatIntelTool


class HybridAnalysisTool(ThreatIntelTool):
    name: str = "hybrid_analysis"
    description: str = "Get sandbox analysis reports for file hashes via Hybrid Analysis"
    api_name: str = "hybrid_analysis"
    api_key_env: str = "HYBRID_ANALYSIS_API_KEY"
    base_url: str = "https://www.hybrid-analysis.com/api/v2"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        headers = {
            "api-key": self._get_api_key(),
            "User-Agent": "Falcon Sandbox",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/search/hash",
                headers=headers,
                data={"hash": ioc_value},
                timeout=20,
            )
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, raw: dict) -> dict:
        if not raw or not isinstance(raw, list):
            return {"source": "hybrid_analysis", "found": False}
        report = raw[0]
        return {
            "source": "hybrid_analysis",
            "found": True,
            "verdict": report.get("verdict", ""),
            "threat_score": report.get("threat_score", 0),
            "threat_level": report.get("threat_level", 0),
            "malware_family": report.get("vx_family", ""),
            "file_type": report.get("type", ""),
            "file_name": report.get("submit_name", ""),
            "analysis_start_time": report.get("analysis_start_time", ""),
            "av_detect": report.get("av_detect", 0),
            "tags": report.get("tags", []),
            "mitre_attcks": report.get("mitre_attcks", []),
        }
