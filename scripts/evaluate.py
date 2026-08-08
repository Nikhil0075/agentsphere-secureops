"""Evaluate the full six-agent chain against ground truth.

    python scripts/evaluate.py --split val --limit 200
    python scripts/evaluate.py --split val --limit 50 --backend live

Writes ``artifacts/metrics/evaluation.json``. This is the file the metrics dashboard reads and the
numbers that go in the deck, so it reports the unflattering ones too: where the agents do worse
than the non-LLM baseline, how often the Verifier had to step in, and how often the chain degraded.

The comparison that matters is agents-vs-baseline **on the same incidents**. A macro F1 quoted
without that comparison says nothing about whether the agent layer earns its cost.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.llm import build_client  # noqa: E402
from app.config import ARTIFACTS, METRICS_DIR, ensure_dirs  # noqa: E402
from app.data import incidents as incidents_mod  # noqa: E402
from app.data import loader  # noqa: E402
from app.data.schema import LABELS  # noqa: E402
from app.evaluation import promotion_gate  # noqa: E402
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow  # noqa: E402
from app.retrieval import hybrid  # noqa: E402
from app.retrieval.base import EntityOverlapRetriever  # noqa: E402
from app.services import scoring  # noqa: E402

OUT = METRICS_DIR / "evaluation.json"
INDEX_DIR = ARTIFACTS / "index"


def _prf(truth: list[str], predicted: list[str]) -> dict:
    """Per-class precision/recall/F1 and the macro average, computed here rather than pulled from
    sklearn so the confusion matrix and the headline numbers cannot disagree."""
    per_class = {}
    for label in LABELS:
        tp = sum(1 for t, p in zip(truth, predicted) if t == label and p == label)
        fp = sum(1 for t, p in zip(truth, predicted) if t != label and p == label)
        fn = sum(1 for t, p in zip(truth, predicted) if t == label and p != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(1 for t in truth if t == label),
        }

    accuracy = sum(1 for t, p in zip(truth, predicted) if t == p) / len(truth) if truth else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "macro_f1": round(
            statistics.fmean(v["f1"] for v in per_class.values()) if per_class else 0.0, 4
        ),
        "per_class": per_class,
        "confusion": {
            t: {p: sum(1 for a, b in zip(truth, predicted) if a == t and b == p) for p in LABELS}
            for t in LABELS
        },
    }


def _calibration(truth: list[str], predicted: list[str], confidence: list[float]) -> dict:
    if not truth:
        return {"brier": 0.0, "expected_calibration_error": 0.0, "bins": []}
    correct = [1.0 if actual == guess else 0.0 for actual, guess in zip(truth, predicted)]
    brier = statistics.fmean((score - outcome) ** 2 for score, outcome in zip(confidence, correct))
    bins = []
    ece = 0.0
    for index in range(10):
        lower, upper = index / 10, (index + 1) / 10
        members = [
            position
            for position, score in enumerate(confidence)
            if lower <= score <= upper and (index == 9 or score < upper)
        ]
        if not members:
            continue
        mean_confidence = statistics.fmean(confidence[position] for position in members)
        accuracy = statistics.fmean(correct[position] for position in members)
        ece += len(members) / len(truth) * abs(mean_confidence - accuracy)
        bins.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(members),
                "confidence": round(mean_confidence, 4),
                "accuracy": round(accuracy, 4),
            }
        )
    return {
        "brier": round(brier, 4),
        "expected_calibration_error": round(ece, 4),
        "bins": bins,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", default="val", choices=["train", "val", "demo", "all"])
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument(
        "--backend",
        choices=["replay", "live", "deterministic", "openai", "cache"],
    )
    parser.add_argument("--out", default=str(OUT))
    parser.add_argument("--current-report", help="same-set report for the currently promoted workflow")
    parser.add_argument("--baseline-report", help="same-set non-LLM baseline report")
    parser.add_argument(
        "--require-promotion",
        action="store_true",
        help="exit non-zero unless the full validation run passes all promotion checks",
    )
    args = parser.parse_args()

    if bool(args.current_report) != bool(args.baseline_report):
        parser.error("--current-report and --baseline-report must be supplied together")
    if args.require_promotion and (args.split != "val" or args.limit != 0):
        parser.error("--require-promotion requires --split val --limit 0")

    ensure_dirs()
    evidence, incidents = loader.load_prepared()
    if args.split != "all":
        incidents = incidents[incidents["split"] == args.split]
    if args.limit:
        incidents = incidents.head(args.limit)
    if incidents.empty:
        print(f"no incidents in split {args.split!r}", file=sys.stderr)
        return 1

    model = scoring.load_baseline()
    retriever = hybrid.load_if_available(INDEX_DIR) or EntityOverlapRetriever(evidence, incidents)
    client = build_client(args.backend)
    workflow = Workflow(client=client, retriever=retriever)

    print(
        f"evaluating {len(incidents):,} incident(s) from split {args.split!r} "
        f"on backend {client.backend}"
    )

    truth: list[str] = []
    agent_pred: list[str] = []
    baseline_pred: list[str] = []
    verdicts: Counter[str] = Counter()
    per_agent_latency: dict[str, list[int]] = {name: [] for name in AGENT_SEQUENCE}
    degraded = 0
    approvals_required = 0
    auto_approved = 0
    disagreements = 0
    cluster_collapse = 0
    confidences: list[float] = []
    cached_calls = 0
    agent_calls = 0
    retries = 0
    input_tokens = 0
    output_tokens = 0
    started = time.perf_counter()

    for n, (_, row) in enumerate(incidents.iterrows(), start=1):
        rows = incidents_mod.evidence_for(evidence, row["incident_id"])
        result = workflow.run(row, rows, baseline_model=model)
        state = result.state

        truth.append(row["label"])
        agent_pred.append(state.triage.label.value if state.triage else "")
        confidences.append(state.triage.confidence if state.triage else 0.0)
        baseline_pred.append(state.baseline.label.value if state.baseline else "")

        if state.verifier:
            verdicts[state.verifier.verdict.value] += 1
        for run in state.runs:
            per_agent_latency[run.agent].append(run.latency_ms)
            agent_calls += 1
            cached_calls += int(run.cached)
            retries += max(0, run.attempts - 1)
            input_tokens += run.prompt_tokens
            output_tokens += run.completion_tokens
        if result.degraded_agents():
            degraded += 1
        if state.requires_approval:
            approvals_required += 1
        if result.gate and result.gate.auto_approved:
            auto_approved += 1
        if state.baseline and state.triage and state.baseline.label != state.triage.label:
            disagreements += 1
        if state.correlation_clusters and result.context.correlation:
            if state.correlation_clusters < result.context.correlation.alert_count:
                cluster_collapse += 1

        if n % 25 == 0:
            print(f"  {n}/{len(incidents)} ...", flush=True)

    elapsed = time.perf_counter() - started
    total = len(truth)

    report = {
        "split": args.split,
        "backend": client.backend,
        "model": getattr(client, "model", ""),
        "incidents": total,
        "wall_seconds": round(elapsed, 2),
        "agents": _prf(truth, agent_pred),
        "calibration": _calibration(truth, agent_pred, confidences),
        "baseline": _prf(truth, [p for p in baseline_pred]) if any(baseline_pred) else None,
        "verifier": {
            "verdicts": dict(verdicts),
            "rejection_rate": round(verdicts["reject"] / total, 4) if total else 0.0,
            "escalation_rate": round(verdicts["escalate"] / total, 4) if total else 0.0,
        },
        "gate": {
            "requires_approval": approvals_required,
            "auto_approved": auto_approved,
            "auto_approval_rate": round(auto_approved / total, 4) if total else 0.0,
        },
        "reliability": {
            "degraded_runs": degraded,
            "degraded_rate": round(degraded / total, 4) if total else 0.0,
            "baseline_disagreement_rate": round(disagreements / total, 4) if total else 0.0,
            "incidents_with_cluster_collapse": cluster_collapse,
            "cache_hit_rate": round(cached_calls / agent_calls, 4) if agent_calls else 0.0,
            "retry_count": retries,
        },
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "estimated_cost_usd": None,
            "cost_note": "No estimate: pricing is intentionally not hardcoded into evaluation artifacts.",
        },
        "latency_ms": {
            name: {
                "mean": round(statistics.fmean(values), 1) if values else 0,
                "max": max(values) if values else 0,
            }
            for name, values in per_agent_latency.items()
        },
    }

    if args.current_report and args.baseline_report:
        current = json.loads(Path(args.current_report).read_text(encoding="utf-8"))
        baseline = json.loads(Path(args.baseline_report).read_text(encoding="utf-8"))
        report["promotion"] = promotion_gate(report, current, baseline)

    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    agents = report["agents"]
    print(f"\n{'=' * 66}")
    print(f"{total} incidents, {elapsed:.1f}s on backend {client.backend}")
    print(f"{'=' * 66}")
    print(f"  agent   accuracy {agents['accuracy']:.4f}   macro F1 {agents['macro_f1']:.4f}")
    if report["baseline"]:
        base = report["baseline"]
        delta = agents["macro_f1"] - base["macro_f1"]
        print(f"  baseline accuracy {base['accuracy']:.4f}   macro F1 {base['macro_f1']:.4f}")
        print(f"  delta (agents - baseline) macro F1 {delta:+.4f}")
    print()
    for label, scores in agents["per_class"].items():
        print(
            f"  {label:16s} P {scores['precision']:.3f}  R {scores['recall']:.3f}  "
            f"F1 {scores['f1']:.3f}  n={scores['support']}"
        )
    print()
    print(f"  verifier verdicts        {dict(verdicts)}")
    print(f"  auto-approval rate       {report['gate']['auto_approval_rate']:.1%}")
    print(f"  baseline disagreement    {report['reliability']['baseline_disagreement_rate']:.1%}")
    print(f"  degraded runs            {degraded}/{total}")
    print(f"\nreport -> {args.out}")
    if args.require_promotion and not report.get("promotion", {}).get("passed", False):
        print("promotion gate failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
