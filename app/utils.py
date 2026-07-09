"""
Shared utility functions for ThreatChain.
"""
import json
import re
import logging

logger = logging.getLogger(__name__)

# Matches a fenced block like ```json ... ``` anywhere in the response
# (LLMs often prepend prose such as "Here is the JSON:").
_FENCE_RE = re.compile(r"```\s*[a-z]*\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)


def parse_llm_json(content: str) -> dict | list:
    """
    Parse JSON from an LLM response that may be wrapped in a markdown
    code fence (``` or ```json or ``` json) and surrounded by prose.

    Raises json.JSONDecodeError if no JSON value can be extracted.
    """
    text = content.strip()

    match = _FENCE_RE.search(text)
    if match:
        text = match.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fall back to the first JSON object/array embedded in the text
        # (prose before it, trailing prose after it, or an unclosed fence).
        starts = [i for i in (text.find("{"), text.find("[")) if i != -1]
        if not starts:
            raise
        value, _ = json.JSONDecoder().raw_decode(text[min(starts):])
        return value
