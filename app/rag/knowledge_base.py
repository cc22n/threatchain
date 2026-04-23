import logging
from langchain_chroma import Chroma
from app.rag.embeddings import get_embeddings
from app.config import settings

logger = logging.getLogger(__name__)

MITRE_COLLECTION = "mitre_attack"

# Module-level singleton so we pay the Chroma connection cost only once
# per process instead of on every similarity search call.
_mitre_vectorstore: Chroma | None = None


def get_mitre_vectorstore() -> Chroma:
    global _mitre_vectorstore
    if _mitre_vectorstore is None:
        _mitre_vectorstore = Chroma(
            collection_name=MITRE_COLLECTION,
            embedding_function=get_embeddings(),
            persist_directory=settings.CHROMA_PERSIST_DIR,
        )
    return _mitre_vectorstore


def mitre_similarity_search(query: str, k: int = 5) -> list:
    vs = get_mitre_vectorstore()
    return vs.similarity_search(query, k=k)
