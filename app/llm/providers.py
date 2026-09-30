import json
import os
from functools import lru_cache
from pathlib import Path
from langchain_core.language_models import BaseChatModel

_CONFIG_PATH = Path(__file__).parent.parent.parent / "ai_config.json"


@lru_cache(maxsize=1)
def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def get_llm(
    provider: str,
    model: str,
    temperature: float = 0.0,
    max_tokens: int = 2048,
    timeout: int = 30,
) -> BaseChatModel:
    config = _load_config()
    provider_cfg = config["providers"].get(provider)
    if not provider_cfg:
        raise ValueError(f"Unknown provider: {provider}")

    api_key_env = provider_cfg.get("api_key_env", "")
    api_key = os.environ.get(api_key_env, "") if api_key_env else ""

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            temperature=temperature,
            max_tokens=max_tokens,
            request_timeout=timeout,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model,
            api_key=api_key,
            temperature=temperature,
            max_tokens_to_sample=max_tokens,
            timeout=timeout,
        )

    if provider == "xai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=provider_cfg.get("base_url", "https://api.x.ai/v1"),
            temperature=temperature,
            max_tokens=max_tokens,
            request_timeout=timeout,
        )

    if provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model,
            google_api_key=api_key,
            temperature=temperature,
            max_output_tokens=max_tokens,
            request_timeout=timeout,
        )

    if provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=model,
            api_key=api_key,
            temperature=temperature,
            max_tokens=max_tokens,
            request_timeout=timeout,
        )

    if provider == "deepseek":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=provider_cfg.get("base_url", "https://api.deepseek.com"),
            temperature=temperature,
            max_tokens=max_tokens,
            request_timeout=timeout,
        )

    raise ValueError(f"Unknown provider: {provider}")
