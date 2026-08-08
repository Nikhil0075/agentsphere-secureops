"""Measure how much a live run actually varies. The empirical answer, not a caveat.

    python scripts/measure_variance.py --dry-run
    python scripts/measure_variance.py --confirm
    python scripts/measure_variance.py --confirm --incidents INC-a,INC-b --runs 5

The presentation path is replay, which is byte-identical by construction. The live path is not:
the active models are reasoning models exposing no ``temperature``, ``top_p`` or seed, and a
schema or grounding retry re-sends an identical prompt, which on any sampling model is a resample.
"How much does that actually move the decision?" is a measurable question, and this measures it.

Two properties this depends on, both enforced by ``NoWriteCache``:

* **Reads always miss.** If run 2 could replay run 1, the measured variance would be zero and the
  number would be worthless.
* **Writes never land.** A variance sweep must never become the source of the responses the demo
  replays -- these are deliberately unvalidated samples.

Stdout is ASCII: the Windows console is cp1252.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.llm import AgentsSDKClient, ResponseCache, model_profile  # noqa: E402
from app.config import ARTIFACTS, METRICS_DIR, ensure_dirs, settings  # noqa: E402
from app.data import incidents as incidents_mod, loader  # noqa: E402
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow  # noqa: E402
from app.retrieval import hybrid  # noqa: E402
from app.retrieval.base import EntityOverlapRetriever  # noqa: E402
from app.services import scoring  # noqa: E402

OUT = METRICS_DIR / "variance.json"

#: Guardrails. This spends money per call; a typo in --runs should not cost a fortune.
MAX_INCIDENTS = 6
MAX_RUNS = 10
MAX_CALLS = 200

#: Observed per-stage latency on the current profile, used only for the time estimate.
SECONDS_PER_STAGE = (3, 25)


class NoWriteCache(ResponseCache):
    """A cache that answers every read with a miss and drops every write.

    Both halves are load-bearing. Serving a read would make run 2 a replay of run 1 and the
    variance would measure nothing. Persisting a write would put unvalidated samples into the
    store the demo replays from.
    """

    def __init__(self) -> None:
        super().__init__(Path(tempfile.mkdtemp(prefix="agentsphere-variance-")))

    def get(self, key: str) -> dict | None:
        return None

    def put(self, key: str, data: dict, meta: dict | None = None) -> None:
        return None


def _spread(values: list[float]) -> dict:
    if not values:
        return {}
    return {
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "spread": round(max(values) - min(values), 4),
        "stdev": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
    }


def _distinct(values: list) -> dict:
    counts = Counter(str(value) for value in values)
    return {
        "values": sorted(counts),
        "counts": dict(counts),
        "n_distinct": len(counts),
        "modal": counts.most_common(1)[0][0] if counts else "",
    }


def _jaccard(sets: list[set]) -> dict:
    if len(sets) < 2:
        return {"exact_match_rate": 1.0, "mean_pairwise_jaccard": 1.0, "union_size": len(sets[0]) if sets else 0}
    pairs, exact = [], 0
    total = 0
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            total += 1
            union = sets[i] | sets[j]
            pairs.append(len(sets[i] & sets[j]) / len(union) if union else 1.0)
            exact += int(sets[i] == sets[j])
    union_all: set = set()
    for value in sets:
        union_all |= value
    return {
        "exact_match_rate": round(exact / total, 4) if total else 1.0,
        "mean_pairwise_jaccard": round(sum(pairs) / len(pairs), 4) if pairs else 1.0,
        "union_size": len(union_all),
    }


def summarise(runs: list[dict]) -> dict:
    """Everything that could differ between two runs of the same incident."""
    triage_labels = [r["triage_label"] for r in runs]
    approvals = [r["requires_approval"] for r in runs]

    fields = {
        "output_hash": {"n_distinct": len({r["output_hash"] for r in runs})},
        "triage": {
            "label": _distinct(triage_labels),
            "confidence": _spread([r["confidence"] for r in runs]),
            "cited_evidence": _jaccard([set(r["cited"]) for r in runs]),
        },
        "verifier": {
            "verdict": _distinct([r["verdict"] for r in runs]),
            "contradictions": _spread([float(r["contradictions"]) for r in runs]),
        },
        "remediation": {
            "recommended_action": _distinct([r["action"] for r in runs]),
            "action_risk": _distinct([r["action_risk"] for r in runs]),
        },
        "detection": {"severity_score": _spread([r["severity"] for r in runs])},
        # Union-Find over the same evidence must produce the same clusters every time. More than
        # one distinct value here is a determinism bug in our own code, not model variance.
        "correlation": {
            "cluster_count": _distinct([r["clusters"] for r in runs]),
            "deterministic": len({r["clusters"] for r in runs}) <= 1,
        },
        "gate": {
            "requires_approval": _distinct(approvals),
            "auto_approved": _distinct([r["auto_approved"] for r in runs]),
        },
        "investigation": {
            "similar_case_ids": _jaccard([set(r["similar"]) for r in runs]),
            "mitre_techniques": _jaccard([set(r["mitre"]) for r in runs]),
        },
        "run_health": {
            "degraded": _distinct([",".join(r["degraded"]) or "none" for r in runs]),
            "resampled": _distinct([",".join(r["resampled"]) or "none" for r in runs]),
            "revision_fired": _distinct([r["revision_fired"] for r in runs]),
        },
        "cost": {
            "latency_ms": _spread([float(r["latency_ms"]) for r in runs]),
            "tokens": _spread([float(r["tokens"]) for r in runs]),
        },
    }

    # The one number a judge cares about: did the decision itself hold still?
    fields["decision_stable"] = (
        len(set(triage_labels)) == 1 and len(set(approvals)) == 1
    )
    return fields


def observe(result) -> dict:
    state = result.state
    return {
        "output_hash": state.output_hash,
        "triage_label": state.triage.label.value if state.triage else "",
        "confidence": state.triage.confidence if state.triage else 0.0,
        "cited": list(state.triage.supporting_evidence_ids) if state.triage else [],
        "verdict": state.verifier.verdict.value if state.verifier else "",
        "contradictions": len(state.verifier.contradictions) if state.verifier else 0,
        "action": state.remediation.recommended_action if state.remediation else "",
        "action_risk": state.remediation.action_risk.value if state.remediation else "",
        "severity": state.detection.severity_score if state.detection else 0.0,
        "clusters": state.correlation_clusters,
        "requires_approval": state.requires_approval,
        "auto_approved": bool(result.gate.auto_approved) if result.gate else False,
        "similar": [c.incident_id for c in state.investigation.similar_cases]
        if state.investigation
        else [],
        "mitre": [m.technique_id for m in state.investigation.mitre_mapping]
        if state.investigation
        else [],
        "degraded": result.degraded_agents(),
        "resampled": result.resampled_agents(),
        "revision_fired": result.revision_fired,
        "latency_ms": result.total_latency_ms(),
        "tokens": sum(r.prompt_tokens + r.completion_tokens for r in state.runs),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true", help="required; this spends money")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and exit 0")
    parser.add_argument("--incidents", default="", help="comma-separated ids; default ranks 1 and 3")
    parser.add_argument("--runs", type=int, default=3, help=f"runs per incident (max {MAX_RUNS})")
    parser.add_argument("--reasoning-effort", default=settings.openai_reasoning_effort)
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args()

    ensure_dirs()
    evidence, incidents = loader.load_prepared()
    model = scoring.load_baseline()
    incidents = scoring.prepare_queue_table(incidents, model)

    if args.incidents:
        targets = [value.strip() for value in args.incidents.split(",") if value.strip()]
    elif "demo_rank" in incidents:
        # Ranks 1 and 3: the case the demo opens on, and the one where the baseline is wrong --
        # the two whose stability actually matters on stage.
        arc = incidents[incidents["demo_rank"].isin([1, 3])].sort_values("demo_rank")
        targets = [str(value) for value in arc["incident_id"]]
    else:
        targets = [str(incidents["incident_id"].iloc[0])]

    unknown = [value for value in targets if value not in set(incidents["incident_id"])]
    if unknown:
        print(f"unknown incident(s): {', '.join(unknown)}", file=sys.stderr)
        return 1

    runs = args.runs
    calls = len(targets) * runs * len(AGENT_SEQUENCE)
    low = calls * SECONDS_PER_STAGE[0] // 60
    high = calls * SECONDS_PER_STAGE[1] // 60
    print(
        f"plan: {len(targets)} incident(s) x {runs} run(s) x {len(AGENT_SEQUENCE)} stage(s) = "
        f"{calls} live calls (more if the triage revision fires); est. {low}-{high} min at the "
        f"observed {SECONDS_PER_STAGE[0]}-{SECONDS_PER_STAGE[1]}s per stage"
    )
    print(f"cache: suppressed (no reads, no writes); the replay cache is untouched")
    print(f"targets: {', '.join(targets)}")

    if len(targets) > MAX_INCIDENTS or runs > MAX_RUNS or runs < 2 or calls > MAX_CALLS:
        print(
            f"refusing: limits are <= {MAX_INCIDENTS} incidents, 2-{MAX_RUNS} runs, "
            f"<= {MAX_CALLS} calls",
            file=sys.stderr,
        )
        return 1

    if args.dry_run:
        return 0
    if not args.confirm:
        print("\nnot confirmed; nothing was called. Re-run with --confirm.", file=sys.stderr)
        return 2
    if not settings.openai_api_key:
        print("live execution requires OPENAI_API_KEY in .env", file=sys.stderr)
        return 1

    cache = NoWriteCache()
    client = AgentsSDKClient(cache=cache)
    retriever = hybrid.load_if_available(ARTIFACTS / "index") or EntityOverlapRetriever(
        evidence, incidents
    )
    workflow = Workflow(client=client, retriever=retriever)

    print()
    observations: dict[str, list[dict]] = {}
    started = time.perf_counter()

    for incident_id in targets:
        row = incidents[incidents["incident_id"] == incident_id].iloc[0]
        rows = incidents_mod.evidence_for(evidence, incident_id)
        observations[incident_id] = []
        for index in range(1, runs + 1):
            result = workflow.run(row, rows, baseline_model=model)
            record = observe(result)
            observations[incident_id].append(record)
            print(
                f"{incident_id} run {index}/{runs}: {record['triage_label'] or '-'} "
                f"@{record['confidence']:.2f} verdict={record['verdict'] or '-'} "
                f"approval={'yes' if record['requires_approval'] else 'no'} "
                f"hash={record['output_hash'][:14]}"
            )

    per_incident = {
        incident_id: summarise(records) for incident_id, records in observations.items()
    }
    stable = sum(1 for entry in per_incident.values() if entry["decision_stable"])

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model_profile": model_profile(),
        "reasoning_effort": args.reasoning_effort,
        "runs_per_incident": runs,
        "cache": "suppressed (no reads, no writes)",
        "total_live_calls": calls,
        "wall_seconds": round(time.perf_counter() - started, 1),
        "decision_stability": round(stable / len(per_incident), 4) if per_incident else 0.0,
        "incidents": per_incident,
    }
    Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(f"\n{'incident':<20} {'label':<14} {'conf spread':<12} {'verdict':<10} hashes  stable")
    print("-" * 84)
    for incident_id, entry in per_incident.items():
        print(
            f"{incident_id:<20} "
            f"{entry['triage']['label']['n_distinct']:<14} "
            f"{entry['triage']['confidence'].get('spread', 0):<12} "
            f"{entry['verifier']['verdict']['n_distinct']:<10} "
            f"{entry['output_hash']['n_distinct']:<7} "
            f"{'yes' if entry['decision_stable'] else 'NO'}"
        )
    print("-" * 84)
    print(
        f"\ndecision stability {payload['decision_stability']:.2f} "
        f"({stable}/{len(per_incident)} incidents produced the same label and gate outcome "
        f"across all {runs} runs)"
    )
    print(f"report -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
