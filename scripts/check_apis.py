"""
check_apis.py - Tests all 17 threat intel APIs with real keys.
Run from project root:
    python scripts/check_apis.py

Uses sample IOCs that are public and well-known so they return real data.
"""
import asyncio
import os
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()


# ------------------------------------------------------------------
# Sample IOCs (public / well-known, safe to query)
# ------------------------------------------------------------------
IP     = "185.220.101.50"    # known Tor exit node
DOMAIN = "malware.testcategory.com"
HASH   = "44d88612fea8a8f36de82e1278abb02f"   # EICAR hash (MD5)
URL    = "http://malware.testcategory.com/"
CVE    = "CVE-2021-44228"    # Log4Shell
EMAIL  = "test@example.com"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


async def test_tool(name: str, tool_cls, ioc_value: str, **kwargs) -> dict:
    key_env = getattr(tool_cls, "__fields__", {}).get("api_key_env") or ""
    try:
        tool_instance = tool_cls()
    except Exception as e:
        return {"name": name, "status": "init_error", "error": str(e), "ms": 0}

    # Check if API key is set
    env_name = tool_instance.api_key_env
    if env_name and not os.environ.get(env_name, ""):
        return {"name": name, "status": "no_key", "error": f"{env_name} not set", "ms": 0}

    start = time.monotonic()
    try:
        result = await tool_instance._arun(ioc_value, **kwargs)
        ms = int((time.monotonic() - start) * 1000)
        return {"name": name, "status": "ok", "ms": ms, "sample": _sample(result)}
    except Exception as e:
        ms = int((time.monotonic() - start) * 1000)
        return {"name": name, "status": "error", "error": str(e)[:120], "ms": ms}


def _sample(result: dict) -> str:
    """One-line summary of the normalized result."""
    parts = []
    for key in ("malicious", "abuse_confidence_score", "noise", "verdict",
                "cvss_score", "malware_family", "classification", "risk",
                "score", "count", "found"):
        if key in result:
            parts.append(f"{key}={result[key]}")
    return ", ".join(parts[:3]) or "ok"


async def run_all():
    from app.tools.virustotal       import VirusTotalTool
    from app.tools.abuseipdb        import AbuseIPDBTool
    from app.tools.shodan           import ShodanTool
    from app.tools.alienvault_otx   import AlienVaultOTXTool
    from app.tools.urlscan          import URLScanTool
    from app.tools.nvd              import NVDTool
    from app.tools.cisa_kev         import CISAKEVTool
    from app.tools.malwarebazaar    import MalwareBazaarTool
    from app.tools.hybrid_analysis  import HybridAnalysisTool
    from app.tools.greynoise        import GreyNoiseTool
    from app.tools.pulsedive        import PulsediveTool
    from app.tools.threatfox        import ThreatFoxTool
    from app.tools.phishtank        import PhishTankTool
    from app.tools.securitytrails   import SecurityTrailsTool
    from app.tools.exploitdb        import ExploitDBTool
    from app.tools.threatcrowd      import ThreatCrowdTool
    from app.tools.haveibeenpwned   import HaveIBeenPwnedTool

    tasks_def = [
        # (display_name, ToolClass, ioc_value, extra_kwargs)
        ("VirusTotal",       VirusTotalTool,      IP,     {"ioc_type": "ip"}),
        ("AbuseIPDB",        AbuseIPDBTool,       IP,     {}),
        ("Shodan",           ShodanTool,          IP,     {}),
        ("AlienVault OTX",   AlienVaultOTXTool,   IP,     {"ioc_type": "ip"}),
        ("URLScan.io",       URLScanTool,         URL,    {}),
        ("NVD (NIST)",       NVDTool,             CVE,    {}),
        ("CISA KEV",         CISAKEVTool,         CVE,    {}),
        ("MalwareBazaar",    MalwareBazaarTool,   HASH,   {}),
        ("Hybrid Analysis",  HybridAnalysisTool,  HASH,   {}),
        ("GreyNoise",        GreyNoiseTool,       IP,     {}),
        ("Pulsedive",        PulsediveTool,       IP,     {}),
        ("ThreatFox",        ThreatFoxTool,       IP,     {}),
        ("PhishTank",        PhishTankTool,       URL,    {}),
        ("SecurityTrails",   SecurityTrailsTool,  DOMAIN, {}),
        ("ExploitDB",        ExploitDBTool,       CVE,    {}),
        ("ThreatCrowd",      ThreatCrowdTool,     IP,     {"ioc_type": "ip"}),
        ("HaveIBeenPwned",   HaveIBeenPwnedTool,  EMAIL,  {}),
    ]

    print(f"\n{BOLD}ThreatChain - API Health Check{RESET}")
    print("=" * 60)
    print(f"Sample IOCs:  IP={IP}  CVE={CVE}")
    print("=" * 60)

    # URLScan has a long poll time — run it in background, rest in parallel
    # Split URLScan out to avoid blocking everything for 40s
    urlscan_task = None
    other_tasks = []

    for name, cls, ioc, kw in tasks_def:
        coro = test_tool(name, cls, ioc, **kw)
        if name == "URLScan.io":
            urlscan_task = asyncio.create_task(coro)
        else:
            other_tasks.append(asyncio.create_task(coro))

    print(f"\nTesting {len(tasks_def)} APIs (URLScan runs async, may take ~40s)...\n")

    results_other = await asyncio.gather(*other_tasks)
    results = list(results_other)
    if urlscan_task:
        results.append(await urlscan_task)

    # Print results
    ok = fail = no_key = 0
    for r in results:
        status = r["status"]
        name   = r["name"]
        ms     = r.get("ms", 0)

        if status == "ok":
            ok += 1
            print(f"  {GREEN}OK{RESET}       {name:<20} {ms:>5}ms  {r.get('sample','')}")
        elif status == "no_key":
            no_key += 1
            print(f"  {YELLOW}NO KEY{RESET}   {name:<20}        {r['error']}")
        else:
            fail += 1
            print(f"  {RED}FAIL{RESET}     {name:<20} {ms:>5}ms  {r.get('error','')}")

    print("\n" + "=" * 60)
    print(f"  {GREEN}OK: {ok}{RESET}   {RED}FAIL: {fail}{RESET}   {YELLOW}NO KEY: {no_key}{RESET}   Total: {len(results)}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(run_all())
