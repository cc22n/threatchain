import asyncio
import httpx
from app.tools.base_tool import ThreatIntelTool

_POLL_INTERVAL = 8
_POLL_RETRIES = 5


class URLScanTool(ThreatIntelTool):
    name: str = "urlscan"
    description: str = "Analyze and scan URLs for malicious content via URLScan.io"
    api_name: str = "urlscan"
    api_key_env: str = "URLSCAN_API_KEY"
    base_url: str = "https://urlscan.io/api/v1"

    async def _call_api(self, ioc_value: str, **kwargs) -> dict:
        headers = {"API-Key": self._get_api_key(), "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=30) as client:
            # Submit scan
            submit = await client.post(
                f"{self.base_url}/scan/",
                headers=headers,
                json={"url": ioc_value, "visibility": "public"},
            )
            submit.raise_for_status()
            data = submit.json()
            scan_uuid = data.get("uuid", "")
            result_url = data.get("result", "")

            if not scan_uuid:
                return {"uuid": "", "result": result_url, "verdicts": {}}

            # Poll for results — URLScan analysis takes ~10 s
            for _ in range(_POLL_RETRIES):
                await asyncio.sleep(_POLL_INTERVAL)
                try:
                    resp = await client.get(
                        f"{self.base_url}/result/{scan_uuid}/",
                        headers={"API-Key": self._get_api_key()},
                    )
                    if resp.status_code == 200:
                        return resp.json()
                    if resp.status_code == 404:
                        # Not ready yet; keep polling
                        continue
                    resp.raise_for_status()
                except httpx.HTTPStatusError:
                    continue

            # Return submission metadata if polling timed out
            return {"uuid": scan_uuid, "result": result_url, "verdicts": {}, "timed_out": True}

    def _normalize(self, raw: dict) -> dict:
        verdicts = raw.get("verdicts", {})
        overall = verdicts.get("overall", {})
        page = raw.get("page", {})
        lists = raw.get("lists", {})
        return {
            "source": "urlscan",
            "scan_id": raw.get("uuid", raw.get("_id", "")),
            "result_url": raw.get("result", ""),
            "url": page.get("url", ""),
            "domain": page.get("domain", ""),
            "ip": page.get("ip", ""),
            "country": page.get("country", ""),
            "malicious": overall.get("malicious", False),
            "score": overall.get("score", 0),
            "categories": overall.get("categories", []),
            "tags": raw.get("tags", []),
            "certificates": len(lists.get("certificates", [])),
            "timed_out": raw.get("timed_out", False),
        }
