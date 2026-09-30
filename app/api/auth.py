import secrets
from fastapi import Header, HTTPException, status
from app.config import settings


async def require_api_key(x_api_key: str = Header(default="")) -> None:
    """
    Dependency that enforces X-API-Key header.
    In production, API_KEY is strictly required (fail-closed).
    If APP_ENV is development and API_KEY is empty, auth is skipped for local ease.
    """
    if not settings.API_KEY:
        if getattr(settings, "APP_ENV", "development") == "production":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server configuration error: API_KEY is required in production",
            )
        return

    # Constant-time comparison to avoid leaking the key via timing.
    if not secrets.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )


def validate_ws_token(token: str | None = None) -> bool:
    """
    Validates token for WebSocket connections via query param or header.
    Returns True if valid, False if rejected.
    """
    if not settings.API_KEY:
        if getattr(settings, "APP_ENV", "development") == "production":
            return False
        return True

    if not token:
        return False

    return secrets.compare_digest(token, settings.API_KEY)
