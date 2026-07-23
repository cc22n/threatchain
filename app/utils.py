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


_MAX_IOC_PROMPT_LENGTH = 512


def sanitize_for_prompt(value: str, max_length: int = _MAX_IOC_PROMPT_LENGTH) -> str:
    """Neutralize an IOC value before embedding it in an agent's LLM prompt.

    url/domain/email-type IOCs can carry attacker-controlled text (a path
    segment, subdomain label, etc). This does not try to detect intent -
    it strips newline/control characters so injected text can't imitate a
    new prompt section (e.g. a "\\n\\nSYSTEM:" break-out) from inside the
    single-line "IOC: <value>" slot, and caps length against token-stuffing.
    ioc_type is not re-validated against ioc_value's shape before this
    point (a caller hitting the API directly can pair an explicit ioc_type
    with an arbitrary ioc_value), so this is the actual choke point, not a
    redundant belt-and-suspenders check.
    """
    cleaned = "".join(ch for ch in value if ch.isprintable())
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "...(truncated)"
    return cleaned
