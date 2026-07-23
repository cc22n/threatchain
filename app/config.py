from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List

# pydantic-settings reads .env only for the fields declared on Settings;
# tools and LLM providers read their API keys from os.environ directly,
# so .env must also be loaded into the process environment.
load_dotenv()


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+psycopg://user:password@localhost:5432/threatchain"
    REDIS_URL: str = "redis://localhost:6379/0"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: List[str] = ["http://localhost:8501", "http://localhost:3000"]
    INVESTIGATION_TIMEOUT_SECONDS: int = 120
    CACHE_TTL_HOURS: int = 24
    CHROMA_PERSIST_DIR: str = "./chroma_data"
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    EMBEDDING_PROVIDER: str = "openai"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    XAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    # Optional: set to require X-API-Key header on mutation endpoints.
    # Leave empty to disable auth (local/dev mode).
    API_KEY: str = ""
    # Telegram bot: token from BotFather, and a closed allowlist of chat_ids
    # (comma-separated). The bot is private by design - an empty allowlist
    # means nobody can use it. Kept as a plain str (not List[int]): pydantic
    # -settings JSON-decodes complex-typed env fields before any validator
    # runs, so an empty or plain comma-separated value raises SettingsError
    # instead of reaching a "before" validator. See telegram_allowlist_ids.
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_ALLOWLIST: str = ""

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    @property
    def telegram_allowlist_ids(self) -> List[int]:
        return [int(x.strip()) for x in self.TELEGRAM_ALLOWLIST.split(",") if x.strip()]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
