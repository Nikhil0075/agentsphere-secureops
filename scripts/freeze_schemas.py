"""Freeze the agent output contracts.

    python scripts/freeze_schemas.py          # write artifacts/schemas/*.json
    python scripts/freeze_schemas.py --check  # fail if anything drifted

The written files are committed. They are the Day 2 exit criterion made checkable: after today,
``--check`` failing means a contract was renegotiated, and every consumer built against it — the
prompts, the validators, the UI, the hashes — is now suspect.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.json_schema import to_openai_schema  # noqa: E402
from app.agents.schemas import AGENT_OUTPUT_MODELS, HumanApproval, WorkflowState  # noqa: E402
from app.config import SCHEMAS_DIR, ensure_dirs  # noqa: E402

FROZEN = {
    **AGENT_OUTPUT_MODELS,
    "human_approval": HumanApproval,
}


def render() -> dict[str, str]:
    out = {
        f"{name}.schema.json": json.dumps(to_openai_schema(model), indent=2, sort_keys=True)
        for name, model in FROZEN.items()
    }
    # WorkflowState is not sent to a model, but freezing it catches accidental state changes.
    out["workflow_state.schema.json"] = json.dumps(
        WorkflowState.model_json_schema(), indent=2, sort_keys=True
    )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify instead of write")
    args = parser.parse_args()

    ensure_dirs()
    rendered = render()

    if args.check:
        drifted = []
        for filename, content in rendered.items():
            path = SCHEMAS_DIR / filename
            if not path.exists():
                drifted.append(f"{filename} (missing)")
            elif path.read_text(encoding="utf-8").strip() != content.strip():
                drifted.append(f"{filename} (changed)")
        if drifted:
            print("SCHEMA DRIFT: " + ", ".join(drifted), file=sys.stderr)
            print("Contracts were frozen on 5 Aug. Re-run without --check only if this change "
                  "is intended, and re-check every consumer.", file=sys.stderr)
            return 1
        print(f"{len(rendered)} schemas match the frozen artifacts.")
        return 0

    for filename, content in rendered.items():
        (SCHEMAS_DIR / filename).write_text(content + "\n", encoding="utf-8")
        print(f"wrote {SCHEMAS_DIR / filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
