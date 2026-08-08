"""Populate and verify replay entries for the curated demo cases.

    python scripts/prewarm_replay.py                 # the six-case arc
    python scripts/prewarm_replay.py --pool showcase # all 30, much slower and dearer
    python scripts/prewarm_replay.py --force         # ignore existing entries and re-warm

This is deliberately an explicit preparation command: it makes paid live model calls. The normal
demo never invokes it.

Two phases, and the second is the one that matters. Warming proves the live calls succeeded;
**verifying** proves the demo will actually replay them -- hermetically, at a full cache hit, with
a reproducible ``output_hash``. A manifest that only recorded phase one would report "ready" for a
set of entries replay might still reject.

Stdout is ASCII: the Windows console is cp1252.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.llm import AgentsSDKClient, ReplayClient, model_profile  # noqa: E402
from app.config import ARTIFACTS, LLM_CACHE_DIR, ensure_dirs  # noqa: E402
from app.data import incidents as incidents_mod, loader  # noqa: E402
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow  # noqa: E402
from app.retrieval import hybrid  # noqa: E402
from app.retrieval.base import EntityOverlapRetriever  # noqa: E402
from app.services import scoring  # noqa: E402

MANIFEST = LLM_CACHE_DIR / "demo_manifest.json"


def select(incidents, pool: str):
    """The target set, in the order the demo walks it."""
    if pool == "arc":
        if "demo_rank" not in incidents:
            return None, "prepared incidents have no demo arc; rerun scripts/prepare_data.py"
        arc = incidents[incidents["demo_rank"].notna()].sort_values("demo_rank")
        if arc.empty:
            return None, "demo arc is empty; rerun scripts/prepare_data.py"
        return arc, ""

    if "is_showcase" not in incidents:
        return None, "prepared incidents have no showcase markers; rerun scripts/prepare_data.py"
    showcase = incidents[incidents["is_showcase"].astype(bool)]
    if showcase.empty:
        return None, "no showcase incidents; rerun scripts/prepare_data.py"
    return showcase.sort_values(["risk_score", "incident_id"], ascending=[False, True]), ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pool",
        choices=["arc", "showcase"],
        default="arc",
        help="arc = the six curated cases (default); showcase = all 30",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-run every stage live even when an entry already exists",
    )
    args = parser.parse_args()

    ensure_dirs()
    evidence, incidents = loader.load_prepared()
    model = scoring.load_baseline()
    incidents = scoring.prepare_queue_table(incidents, model)

    targets, problem = select(incidents, args.pool)
    if targets is None:
        print(problem, file=sys.stderr)
        return 1

    retriever = hybrid.load_if_available(ARTIFACTS / "index") or EntityOverlapRetriever(
        evidence, incidents
    )

    # Warming through a fill-enabled replay client rather than a bare live client means a resumed
    # prewarm skips stages that are already cached instead of paying for them twice.
    warm_client = (
        AgentsSDKClient() if args.force else ReplayClient(allow_live_fill=True)
    )
    warm = Workflow(client=warm_client, retriever=retriever)

    print(f"pool: {args.pool}, {len(targets)} incident(s)")
    print(f"profile: {json.dumps(model_profile(), sort_keys=True)}\n")

    completed: list[str] = []
    failures: dict[str, list[str]] = {}
    live_results: dict[str, dict] = {}

    for _, incident in targets.iterrows():
        incident_id = str(incident["incident_id"])
        rows = incidents_mod.evidence_for(evidence, incident_id)
        result = warm.run(incident, rows, baseline_model=model)
        degraded = result.degraded_agents()

        live_results[incident_id] = {
            "live_output_hash": result.state.output_hash,
            "revision_fired": result.revision_fired,
            "resampled_agents": result.resampled_agents(),
        }
        if degraded:
            failures[incident_id] = degraded
            print(f"warm  {incident_id}: DEGRADED {','.join(degraded)}")
        else:
            completed.append(incident_id)
            print(f"warm  {incident_id}: ok")

    # --- phase two: prove the demo can actually replay what we just warmed ---------------------
    # A hermetic client, exactly as the demo runs. If this cannot serve every stage from cache,
    # the prewarm did not achieve what it was for, whatever phase one reported.
    print()
    verify = Workflow(client=ReplayClient(), retriever=retriever)
    arc_entries: dict[str, dict] = {}
    replay_verified = True

    for _, incident in targets.iterrows():
        incident_id = str(incident["incident_id"])
        rows = incidents_mod.evidence_for(evidence, incident_id)
        rank = incident.get("demo_rank")
        key = str(int(rank)) if rank is not None and rank == rank else incident_id

        started = time.perf_counter()
        try:
            replayed = verify.run(incident, rows, baseline_model=model)
        except Exception as exc:  # noqa: BLE001 - report it, do not abort the other cases
            replay_verified = False
            print(f"check {incident_id}: REPLAY FAILED {type(exc).__name__}: {exc}")
            continue
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        runs = replayed.state.runs
        all_cached = bool(runs) and all(run.cached for run in runs)
        clean = replayed.degraded_agents() == [] and len(runs) == len(AGENT_SEQUENCE)
        ok = all_cached and clean
        replay_verified = replay_verified and ok

        live = live_results.get(incident_id, {})
        arc_entries[key] = {
            "incident_id": incident_id,
            "demo_role": str(incident.get("demo_role", "") or ""),
            "cache_hits": sum(1 for run in runs if run.cached),
            "all_runs_cached": all_cached,
            "replay_output_hash": replayed.state.output_hash,
            "replay_latency_ms": elapsed_ms,
            **live,
        }
        status = "ok" if ok else "NOT REPLAYABLE"
        print(
            f"check {incident_id}: {status}  {sum(1 for r in runs if r.cached)}/{len(runs)} cached"
            f"  {elapsed_ms}ms"
        )

    revision_fired = [
        incident_id
        for incident_id, entry in live_results.items()
        if entry.get("revision_fired")
    ]

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model_profile": model_profile(),
        "pool": args.pool,
        "expected": int(len(targets)),
        "completed": completed,
        "failures": failures,
        "arc": arc_entries,
        "replay_verified": replay_verified,
        "revision_fired": revision_fired,
        "ready": len(completed) == len(targets) and replay_verified,
    }
    MANIFEST.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(f"\nmanifest -> {MANIFEST}")
    print(f"ready: {payload['ready']}  (warmed {len(completed)}/{len(targets)}, "
          f"replay verified {replay_verified})")
    if revision_fired:
        print(
            f"note: {len(revision_fired)} case(s) ran the live triage revision pass. Their live "
            "output_hash differs from the replayed one by design -- replay runs the six-stage "
            "sequence only. See app/orchestration/workflow.py."
        )
    return 0 if payload["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
