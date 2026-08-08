"""Inspect and prune the replay cache.

    python scripts/cache_admin.py --audit
    python scripts/cache_admin.py --prune-dead --confirm
    python scripts/cache_admin.py --prune-suspect --confirm
    python scripts/cache_admin.py --prune-foreign --confirm

Replay serves whatever JSON sits in ``artifacts/llm_cache``, so that directory is part of the
demo's trusted computing base. This is the tool that says what is in it.

Nothing here deletes. Pruned entries are moved to ``artifacts/llm_cache/.pruned/<timestamp>/``,
because discovering on demo morning that the wrong sweep was pruned is not a recoverable mistake.

Stdout is ASCII: the Windows console is cp1252.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.llm import ResponseCache  # noqa: E402
from app.config import DATA_PROCESSED, LLM_CACHE_DIR  # noqa: E402
from app.agents.llm import model_profile  # noqa: E402

PRUNED_DIR = LLM_CACHE_DIR / ".pruned"

#: Why an entry can never be served, in the order the audit reports them.
DEAD = "dead"          # no prompt_version: written before versioning, key is unreachable
SUSPECT = "suspect"    # zero latency with real token counts: a test double wrote this
FOREIGN = "foreign"    # a model outside the active profile
CURRENT = "current"    # usable under the active profile


def classify(entry: dict, active_models: set[str], prompt_version: str) -> str:
    meta = entry.get("meta") or {}
    if not str(meta.get("prompt_version", "")):
        return DEAD
    latency = int(meta.get("latency_ms", 0) or 0)
    tokens = int(meta.get("prompt_tokens", 0) or 0) + int(meta.get("completion_tokens", 0) or 0)
    if latency == 0 and tokens > 0:
        return SUSPECT
    if str(meta.get("model", "")) not in active_models:
        return FOREIGN
    if str(meta.get("prompt_version", "")) != prompt_version:
        return FOREIGN
    return CURRENT


def scan() -> tuple[dict[str, list[Path]], Counter]:
    profile = model_profile()
    active = {profile["support"], profile["judge"]}
    version = profile["prompt_version"]

    buckets: dict[str, list[Path]] = {DEAD: [], SUSPECT: [], FOREIGN: [], CURRENT: []}
    census: Counter = Counter()

    for path in sorted(LLM_CACHE_DIR.glob("*.json")):
        if len(path.stem) != 64:
            continue  # demo_manifest.json and friends are not cache entries
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            buckets[SUSPECT].append(path)
            census[("unreadable", "-")] += 1
            continue
        meta = entry.get("meta") or {}
        census[(str(meta.get("model", "")) or "-", str(meta.get("prompt_version", "")) or "-")] += 1
        buckets[classify(entry, active, version)].append(path)

    return buckets, census


def arc_readiness() -> str:
    """How many of the six curated cases the manifest says are prewarmed."""
    manifest = LLM_CACHE_DIR / "demo_manifest.json"
    if not manifest.exists():
        return "demo_manifest.json missing; run: python scripts/prewarm_replay.py"
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "demo_manifest.json unreadable"

    expected = int(payload.get("expected", 0) or 0)
    completed = len(payload.get("completed", []) or [])
    profile_matches = payload.get("model_profile") == model_profile()
    parts = [f"{completed}/{expected} curated cases warmed"]
    parts.append("profile matches" if profile_matches else "PROFILE CHANGED since prewarm")
    parts.append("replay verified" if payload.get("replay_verified") else "replay NOT verified")
    parts.append("ready" if payload.get("ready") else "NOT ready")
    return ", ".join(parts)


def audit() -> int:
    buckets, census = scan()
    total = sum(len(paths) for paths in buckets.values())

    profile = model_profile()
    print(f"cache      {LLM_CACHE_DIR}")
    print(f"active     support={profile['support']} judge={profile['judge']} "
          f"prompt_version={profile['prompt_version']}")
    print(f"entries    {total}\n")

    print(f"{'model':<24} {'prompt_version':<16} count")
    print("-" * 52)
    for (model, version), count in sorted(census.items(), key=lambda item: -item[1]):
        print(f"{model:<24} {version:<16} {count}")
    print("-" * 52)

    print(f"\n  current  {len(buckets[CURRENT]):>4}  servable under the active profile")
    print(f"  foreign  {len(buckets[FOREIGN]):>4}  a different model or prompt version")
    print(f"  dead     {len(buckets[DEAD]):>4}  no prompt_version; the key can never be hit")
    print(f"  suspect  {len(buckets[SUSPECT]):>4}  zero latency with real tokens; not a live response")

    print(f"\ndemo arc   {arc_readiness()}")

    if buckets[SUSPECT]:
        print("\nWARNING: suspect entries are fabricated responses sitting in the store the demo")
        print("         replays from. Remove them: --prune-suspect --confirm")
    return 0


def prune(kind: str, confirm: bool) -> int:
    buckets, _ = scan()
    paths = buckets[kind]
    if not paths:
        print(f"nothing to prune: 0 {kind} entries")
        return 0

    if not confirm:
        print(f"would move {len(paths)} {kind} entry(ies) out of the cache.")
        print("re-run with --confirm to do it.")
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = PRUNED_DIR / f"{stamp}-{kind}"
    destination.mkdir(parents=True, exist_ok=True)
    for path in paths:
        shutil.move(str(path), str(destination / path.name))

    print(f"moved {len(paths)} {kind} entry(ies) -> {destination}")
    print("nothing was deleted; move them back to undo.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true", help="census and readiness, changes nothing")
    parser.add_argument("--prune-dead", action="store_true", help="entries with no prompt_version")
    parser.add_argument("--prune-suspect", action="store_true", help="test-double residue")
    parser.add_argument("--prune-foreign", action="store_true", help="outside the active profile")
    parser.add_argument("--confirm", action="store_true", help="required for any prune")
    args = parser.parse_args()

    if not LLM_CACHE_DIR.exists():
        print(f"no cache at {LLM_CACHE_DIR}", file=sys.stderr)
        return 1

    requested = [
        (DEAD, args.prune_dead),
        (SUSPECT, args.prune_suspect),
        (FOREIGN, args.prune_foreign),
    ]
    selected = [kind for kind, wanted in requested if wanted]

    if not selected or args.audit:
        code = audit()
        if not selected:
            return code
        print()

    status = 0
    for kind in selected:
        status = prune(kind, args.confirm) or status
    return status


if __name__ == "__main__":
    raise SystemExit(main())
