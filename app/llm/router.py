from langchain_core.language_models import BaseChatModel
from app.llm.providers import get_llm, _load_config


def get_llm_for_agent(agent_name: str) -> BaseChatModel:
    config = _load_config()
    routing = config["agent_routing"].get(agent_name)
    if not routing:
        raise ValueError(f"No routing config for agent: {agent_name}")

    def _build(path: str) -> BaseChatModel:
        provider, model = path.split("/", 1)
        return get_llm(provider, model)

    try:
        return _build(routing["primary"])
    except Exception:
        return _build(routing["fallback"])
