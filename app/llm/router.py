from app.llm.providers import get_llm, _load_config
from app.llm.fallback import LLMWithFallback


def get_llm_for_agent(agent_name: str) -> LLMWithFallback:
    """
    Returns LLMWithFallback so runtime API errors (400, 429, 503) automatically
    retry on the fallback model, not just construction-time errors.
    """
    config = _load_config()
    routing = config["agent_routing"].get(agent_name)
    if not routing:
        raise ValueError(f"No routing config for agent: {agent_name}")

    def _build(path: str):
        provider, model = path.split("/", 1)
        return get_llm(provider, model)

    primary = _build(routing["primary"])
    fallback = _build(routing["fallback"])
    return LLMWithFallback(primary=primary, fallback=fallback)
