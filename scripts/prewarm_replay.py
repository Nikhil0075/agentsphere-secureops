"""Populate and verify replay entries for the curated demo cases.

    python scripts/prewarm_replay.py --dry-run
    python scripts/prewarm_replay.py --verify-only
    python scripts/prewarm_replay.py --max-live-stages 6   # incremental, at most one clean case
    python scripts/prewarm_replay.py --max-live-stages 36  # six-case arc, no-retry nominal cap

The command refuses to make a paid call unless ``--max-live-stages`` is supplied. Use
``--dry-run`` first to inspect the target and worst-case request envelope without constructing a
live client or reading an API key.

``--verify-only`` runs the curated arc through the hermetic replay client and refreshes the
manifest. It never constructs a live client, so it is safe after a deterministic policy change.

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

from app.agents.llm import AgentsSDKClient, LLMError, ReplayClient, model_profile  # noqa: E402
from app.config import ARTIFACTS, LLM_CACHE_DIR, ensure_dirs, settings  # noqa: E402
from app.data.demo_arc import ARC_BY_RANK  # noqa: E402
from app.data import incidents as incidents_mod, loader  # noqa: E402
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow  # noqa: E402
from app.retrieval import hybrid  # noqa: E402
from app.retrieval.base import EntityOverlapRetriever  # noqa: E402
from app.services import scoring  # noqa: E402

MANIFEST = LLM_CACHE_DIR / "demo_manifest.json"


class LiveStageBudget:
    """Hard ceiling around paid stage attempts.

    The wrapper sits *inside* ReplayClient, so cache hits cost nothing and do not consume budget.
    Agent retries do consume another unit. A stage may still use several Responses API turns for
    bounded tool calls, but no additional agent stage can start after this counter is exhausted.
    """

    def __init__(self, client, maximum: int) -> None:
        if maximum < 1:
            raise ValueError("maximum live stages must be positive")
        self.client = client
        self.maximum = maximum
        self.used = 0
        self.backend = getattr(client, "backend", "live")
        self.model = getattr(client, "model", "")

    @property
    def exhausted(self) -> bool:
        return self.used >= self.maximum

    def complete_structured(self, **kwargs):
        if self.exhausted:
            raise LLMError(
                f"paid live-stage budget exhausted ({self.used}/{self.maximum}); "
                "rerun with a new explicit budget to continue"
            )
        self.used += 1
        return self.client.complete_structured(**kwargs)


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


def expected_auto_approval(incident) -> bool | None:
    """Expected gate beat for a ranked arc case; unranked showcase cases have no contract."""
    rank = incident.get("demo_rank")
    if rank is None or rank != rank:
        return None
    role = ARC_BY_RANK.get(int(rank))
    return role.expected_auto_approved if role else None


def outcome_snapshot(result, expected: bool | None) -> dict:
    gate = result.gate
    actual = bool(gate and gate.auto_approved)
    return {
        "expected_auto_approved": expected,
        "auto_approved": actual,
        "matches_arc_contract": expected is None or actual == expected,
        "requires_approval": bool(result.state.requires_approval),
        "triage_label": result.label,
        "triage_confidence": round(result.confidence, 4),
        "verifier_verdict": (
            result.state.verifier.verdict.value if result.state.verifier else "missing"
        ),
        "action": (
            result.state.remediation.recommended_action if result.state.remediation else ""
        ),
        "action_risk": gate.action_risk if gate else "unknown",
        "failed_policies": gate.failed_policies() if gate else [],
    }


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
    parser.add_argument(
        "--max-live-stages",
        type=int,
        help=(
            "required hard ceiling on paid agent-stage attempts; retries consume budget, "
            "cache hits do not"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show the target and request envelope; never construct a live client",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="audit cached replay and refresh the manifest; never construct a live client",
    )
    args = parser.parse_args()

    if args.dry_run and args.verify_only:
        print("--dry-run and --verify-only are mutually exclusive", file=sys.stderr)
        return 2
    if args.verify_only and (args.max_live_stages is not None or args.force):
        print(
            "--verify-only cannot be combined with --max-live-stages or --force",
            file=sys.stderr,
        )
        return 2
    if not args.dry_run and not args.verify_only and args.max_live_stages is None:
        print(
            "REFUSED: paid prewarm requires --max-live-stages N. "
            "Run with --dry-run first.",
            file=sys.stderr,
        )
        return 2
    if args.max_live_stages is not None and args.max_live_stages < 1:
        print("--max-live-stages must be positive", file=sys.stderr)
        return 2

    ensure_dirs()
    evidence, incidents = loader.load_prepared()
    model = scoring.load_baseline()
    incidents = scoring.prepare_queue_table(incidents, model)

    targets, problem = select(incidents, args.pool)
    if targets is None:
        print(problem, file=sys.stderr)
        return 1

    nominal = len(targets) * len(AGENT_SEQUENCE)
    retry_ceiling = len(targets) * (len(AGENT_SEQUENCE) + 3) * (
        settings.llm_max_retries + 1
    )
    if args.dry_run:
        print("DRY RUN - no live client constructed; no network request can occur")
        print(f"pool: {args.pool}, {len(targets)} incident(s)")
        print(f"profile: {json.dumps(model_profile(), sort_keys=True)}")
        print(f"nominal uncached stages: {nominal}")
        print(
            f"absolute stage-attempt envelope with retries/revision: {retry_ceiling}; "
            "choose a smaller explicit budget for an incremental warm"
        )
        return 0

    retriever = hybrid.load_if_available(ARTIFACTS / "index") or EntityOverlapRetriever(
        evidence, incidents
    )

    print(f"pool: {args.pool}, {len(targets)} incident(s)")
    print(f"profile: {json.dumps(model_profile(), sort_keys=True)}\n")

    completed: list[str] = []
    failures: dict[str, list[str]] = {}
    live_outcome_failures: dict[str, dict] = {}
    live_results: dict[str, dict] = {}
    historical_live_outcome_failures: dict[str, dict] = {}
    live_budget = None

    if args.verify_only:
        print("VERIFY ONLY - no live client constructed; no OpenAI request can occur\n")
        attempted = [incident for _, incident in targets.iterrows()]
        try:
            prior = json.loads(MANIFEST.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            prior = {}
        historical_live_outcome_failures = prior.get(
            "historical_live_outcome_failures",
            prior.get("live_outcome_failures", {}),
        )
        for entry in (prior.get("arc", {}) or {}).values():
            incident_id = str(entry.get("incident_id", ""))
            if not incident_id:
                continue
            live_results[incident_id] = {
                key: entry[key]
                for key in (
                    "live_output_hash",
                    "revision_fired",
                    "resampled_agents",
                    "outcome",
                )
                if key in entry
            }
    else:
        # Warming through a fill-enabled replay client rather than a bare live client means a
        # resumed prewarm skips stages that are already cached instead of paying for them twice.
        live_budget = LiveStageBudget(AgentsSDKClient(), args.max_live_stages)
        warm_client = (
            live_budget
            if args.force
            else ReplayClient(live=live_budget, allow_live_fill=True)
        )
        warm = Workflow(client=warm_client, retriever=retriever)

        attempted = []
        for _, incident in targets.iterrows():
            if live_budget.exhausted:
                print(
                    f"budget exhausted at {live_budget.used}/{live_budget.maximum}; "
                    "stopping before the next incident"
                )
                break
            incident_id = str(incident["incident_id"])
            attempted.append(incident)
            rows = incidents_mod.evidence_for(evidence, incident_id)
            result = warm.run(incident, rows, baseline_model=model)
            degraded = result.degraded_agents()
            outcome = outcome_snapshot(result, expected_auto_approval(incident))

            live_results[incident_id] = {
                "live_output_hash": result.state.output_hash,
                "revision_fired": result.revision_fired,
                "resampled_agents": result.resampled_agents(),
                "outcome": outcome,
            }
            if not outcome["matches_arc_contract"]:
                live_outcome_failures[incident_id] = outcome
            if degraded:
                failures[incident_id] = degraded
                print(f"warm  {incident_id}: DEGRADED {','.join(degraded)}")
            else:
                completed.append(incident_id)
                print(
                    f"warm  {incident_id}: "
                    + ("ok" if outcome["matches_arc_contract"] else "WRONG AUTONOMY OUTCOME")
                )

    # --- phase two: prove the demo can actually replay what we just warmed ---------------------
    # A hermetic client, exactly as the demo runs. If this cannot serve every stage from cache,
    # the prewarm did not achieve what it was for, whatever phase one reported.
    print()
    verify = Workflow(client=ReplayClient(), retriever=retriever)
    arc_entries: dict[str, dict] = {}
    replay_outcome_failures: dict[str, dict] = {}
    replay_verified = True
    replay_completed: list[str] = []
    replay_failures: dict[str, list[str]] = {}

    for incident in attempted:
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
        replay_outcome = outcome_snapshot(replayed, expected_auto_approval(incident))
        if not replay_outcome["matches_arc_contract"]:
            replay_outcome_failures[incident_id] = replay_outcome
        ok = all_cached and clean and replay_outcome["matches_arc_contract"]
        replay_verified = replay_verified and ok
        if clean:
            replay_completed.append(incident_id)
        else:
            replay_failures[incident_id] = replayed.degraded_agents()

        live = live_results.get(incident_id, {})
        arc_entries[key] = {
            "incident_id": incident_id,
            "demo_role": str(incident.get("demo_role", "") or ""),
            "cache_hits": sum(1 for run in runs if run.cached),
            "all_runs_cached": all_cached,
            "replay_output_hash": replayed.state.output_hash,
            "replay_latency_ms": elapsed_ms,
            "replay_outcome": replay_outcome,
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

    # In verify-only mode the current replay is authoritative for cache readiness and the current
    # deterministic gate. Historical live outcomes remain available for audit, but an obsolete
    # pre-policy gate decision must not make a valid replay look stale.
    if args.verify_only:
        completed = replay_completed
        failures = replay_failures
        live_outcome_failures = {}

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model_profile": model_profile(),
        "pool": args.pool,
        "expected": int(len(targets)),
        "completed": completed,
        "failures": failures,
        "live_outcome_failures": live_outcome_failures,
        "historical_live_outcome_failures": historical_live_outcome_failures,
        "replay_outcome_failures": replay_outcome_failures,
        "arc": arc_entries,
        "replay_verified": replay_verified,
        "revision_fired": revision_fired,
        "verification_mode": "replay_only" if args.verify_only else "live_then_replay",
        "ready": (
            len(completed) == len(targets)
            and replay_verified
            and not live_outcome_failures
            and not replay_outcome_failures
        ),
    }
    MANIFEST.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(f"\nmanifest -> {MANIFEST}")
    if live_budget is None:
        print("paid live stages used: 0 (verify-only)")
    else:
        print(f"paid live stages used: {live_budget.used}/{live_budget.maximum}")
    print(f"ready: {payload['ready']}  (warmed {len(completed)}/{len(targets)}, "
          f"replay verified {replay_verified})")
    if live_outcome_failures or replay_outcome_failures:
        affected = sorted(set(live_outcome_failures) | set(replay_outcome_failures))
        print(
            "NOT READY: autonomy contract mismatch for "
            + ", ".join(affected)
        )
    if revision_fired:
        print(
            f"note: {len(revision_fired)} case(s) ran the live triage revision pass. Their live "
            "output_hash differs from the replayed one by design -- replay runs the six-stage "
            "sequence only. See app/orchestration/workflow.py."
        )
    return 0 if payload["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
