"""
seed_api_configs.py - Seed the api_configs table with 17 threat intel APIs.

Idempotent upsert: if API exists, update base_url/rate_limits/priority/is_active
but preserve requests_today and last_used_at counters.

Run from project root:
    python scripts/seed_api_configs.py
"""
import sys
import asyncio
import json
from pathlib import Path

# Windows event loop policy
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load env vars before importing app modules
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import insert, update, select
from app.database import AsyncSessionLocal
from app.models.config import ApiConfig


# Priority mapping: higher number = lower priority
PRIORITY_MAP = {
    "virustotal": 1,
    "abuseipdb": 1,
    "alienvault_otx": 1,
    "nvd": 1,
    "cisa_kev": 1,
    "threatfox": 1,
    "shodan": 2,
    "urlscan": 2,
    "securitytrails": 2,
    "hybrid_analysis": 2,
    "malwarebazaar": 2,
    "phishtank": 2,
    "exploitdb": 2,
    "greynoise": 3,
    "pulsedive": 3,
    "threatcrowd": 3,
    "haveibeenpwned": 3,
}

ACTIVE_STATUS = {
    "threatcrowd": False,  # Service is dead
}


async def seed_api_configs():
    """Load APIs from api_config.json and upsert into database."""

    # Read api_config.json
    config_file = Path(__file__).parent.parent / "api_config.json"
    with open(config_file, "r") as f:
        config_data = json.load(f)

    apis = config_data.get("apis", {})

    async with AsyncSessionLocal() as session:
        async with session.begin():
            for api_name, api_info in apis.items():
                base_url = api_info.get("base_url", "")
                api_key_env = api_info.get("api_key_env") or None
                rate_limit_per_day = api_info.get("rate_limit_per_day", 1000)
                rate_limit_per_minute = api_info.get("rate_limit_per_minute", 60)
                priority = PRIORITY_MAP.get(api_name, 5)
                is_active = ACTIVE_STATUS.get(api_name, True)

                # Check if API already exists
                result = await session.execute(
                    select(ApiConfig).where(ApiConfig.api_name == api_name)
                )
                existing = result.scalars().first()

                if existing:
                    # Update existing record (preserve requests_today and last_used_at)
                    existing.base_url = base_url
                    existing.api_key_env = api_key_env
                    existing.rate_limit_per_day = rate_limit_per_day
                    existing.rate_limit_per_minute = rate_limit_per_minute
                    existing.priority = priority
                    existing.is_active = is_active
                    await session.merge(existing)
                    print(f"  Updated: {api_name}")
                else:
                    # Insert new record
                    new_api = ApiConfig(
                        api_name=api_name,
                        base_url=base_url,
                        api_key_env=api_key_env,
                        rate_limit_per_day=rate_limit_per_day,
                        rate_limit_per_minute=rate_limit_per_minute,
                        priority=priority,
                        is_active=is_active,
                    )
                    session.add(new_api)
                    print(f"  Inserted: {api_name}")

        # Commit the transaction
        await session.flush()

    print("\nSeeding complete.")


async def verify_count():
    """Verify that 17 APIs are in the database."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ApiConfig))
        apis = result.scalars().all()
        print(f"\nTotal APIs in database: {len(apis)}")
        for api in sorted(apis, key=lambda x: x.api_name):
            status = "[ACTIVE]" if api.is_active else "[INACTIVE]"
            print(f"  {status} {api.api_name:<20} priority={api.priority} "
                  f"daily={api.rate_limit_per_day:>5} per_min={api.rate_limit_per_minute:>3}")


async def main():
    print("Seeding api_configs table with 17 threat intel APIs...\n")
    try:
        await seed_api_configs()
        await verify_count()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
