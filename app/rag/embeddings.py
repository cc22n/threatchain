from langchain_openai import OpenAIEmbeddings
from app.config import settings

_embeddings: OpenAIEmbeddings | None = None


def get_embeddings() -> OpenAIEmbeddings:
    """Return a module-level singleton to avoid reconstructing the httpx
    client on every call."""
    global _embeddings
    if _embeddings is None:
        _embeddings = OpenAIEmbeddings(
            model=settings.EMBEDDING_MODEL,
            api_key=settings.OPENAI_API_KEY,
        )
    return _embeddings
