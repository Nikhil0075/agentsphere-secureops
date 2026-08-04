"""Pydantic model -> OpenAI strict structured-output JSON Schema.

OpenAI's strict mode is fussier than plain JSON Schema: every object must set
``additionalProperties: false``, every property must appear in ``required`` (optionality is
expressed with a null union instead), and ``$ref``/``$defs`` must resolve. Pydantic's own
``model_json_schema()`` satisfies none of that by default, so this module adapts it.

The adaptation is deterministic and is itself frozen — the frozen artifact is what the model is
sent, so it has to be the thing under test.
"""

from __future__ import annotations

import copy
from typing import Any

from app.agents.schemas import StrictModel

_STRIPPED_KEYS = {"default", "examples", "$comment"}


def _harden(node: Any) -> Any:
    if isinstance(node, list):
        return [_harden(item) for item in node]
    if not isinstance(node, dict):
        return node

    out = {k: _harden(v) for k, v in node.items() if k not in _STRIPPED_KEYS}

    if out.get("type") == "object" or "properties" in out:
        out.setdefault("type", "object")
        out["additionalProperties"] = False
        properties = out.get("properties", {})
        # Strict mode requires every declared property to be required.
        out["required"] = sorted(properties)
    return out


def to_openai_schema(model: type[StrictModel]) -> dict:
    """JSON Schema for ``model``, valid for OpenAI strict structured output."""
    raw = model.model_json_schema(ref_template="#/$defs/{model}")
    schema = _harden(copy.deepcopy(raw))
    schema.setdefault("title", model.__name__)
    return schema


def response_format(model: type[StrictModel], name: str) -> dict:
    """The ``response_format`` payload for a chat completion."""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": name,
            "strict": True,
            "schema": to_openai_schema(model),
        },
    }
