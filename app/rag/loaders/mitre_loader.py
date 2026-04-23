import json
import logging
from pathlib import Path
from langchain_core.documents import Document
from langchain_chroma import Chroma
from app.rag.embeddings import get_embeddings
from app.config import settings

logger = logging.getLogger(__name__)

BUNDLE_PATH = Path(__file__).parent.parent.parent.parent / "knowledge_base" / "mitre" / "enterprise-attack.json"
MITRE_COLLECTION = "mitre_attack"


def _is_indexed(persist_dir: str) -> bool:
    vs = Chroma(
        collection_name=MITRE_COLLECTION,
        embedding_function=get_embeddings(),
        persist_directory=persist_dir,
    )
    count = vs._collection.count()
    logger.info("ChromaDB mitre_attack collection has %d documents", count)
    return count > 0


def _parse_stix_bundle(bundle_path: Path) -> list[Document]:
    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.load(f)

    docs = []
    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "")
        if obj_type not in ("attack-pattern", "malware", "tool", "course-of-action"):
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        if not description:
            continue

        external = obj.get("external_references", [])
        technique_id = next(
            (r.get("external_id", "") for r in external if r.get("source_name") == "mitre-attack"),
            "",
        )
        tactic_refs = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        tactics_str = ", ".join(tactic_refs) if tactic_refs else "unknown"
        content = f"Technique: {technique_id} - {name}\nTactics: {tactics_str}\n\n{description}"
        docs.append(Document(
            page_content=content,
            metadata={
                "technique_id": technique_id,
                "technique_name": name,
                "tactics": tactics_str,
                "type": obj_type,
                "stix_id": obj.get("id", ""),
            },
        ))

    logger.info("Parsed %d MITRE documents from STIX bundle", len(docs))
    return docs


def load_mitre_index(force: bool = False) -> None:
    persist_dir = settings.CHROMA_PERSIST_DIR

    if not force and _is_indexed(persist_dir):
        logger.info("MITRE ATT&CK already indexed, skipping")
        return

    if not BUNDLE_PATH.exists():
        raise FileNotFoundError(
            f"STIX bundle not found at {BUNDLE_PATH}. "
            "Download enterprise-attack.json from https://github.com/mitre/cti"
        )

    docs = _parse_stix_bundle(BUNDLE_PATH)
    embeddings = get_embeddings()

    batch_size = 100
    vs = Chroma(
        collection_name=MITRE_COLLECTION,
        embedding_function=embeddings,
        persist_directory=persist_dir,
    )
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        vs.add_documents(batch)
        logger.info("Indexed batch %d/%d (%d docs)", i // batch_size + 1, (len(docs) // batch_size) + 1, len(batch))

    logger.info("MITRE ATT&CK indexing complete: %d documents", len(docs))
