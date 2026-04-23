"""
Shared utility functions for ThreatChain.
"""
import json
import re
import logging

logger = logging.getLogger(__name__)

# Matches optional opening fence like ```json, ``` json, or just ```,
# captures inner content, then matches optional closing fence ```.
_FENCE_RE = re.compile(r"^```\s*[a-z]*\s*\n?(.*?)(?:```\s*)?$", re.DOTALL | re.IGNORECASE)


def parse_llm_json(content: str) -> dict | list:
    """
    Parse JSON from an LLM response that may be wrapped in a markdown
    code fence (``` or ```json or ``` json).

    Raises json.JSONDecodeError if parsing fails.
    """
    text = content.strip()

    match = _FENCE_RE.match(text)
    if match:
        text = match.group(1).strip()

    return json.loads(text)
