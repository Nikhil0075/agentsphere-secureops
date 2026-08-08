"""Decision-complete quality gate for promoting a new agent workflow."""

from __future__ import annotations

from typing import Any


def _agents(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("agents") or report


def _macro_f1(report: dict[str, Any]) -> float:
    return float(_agents(report).get("macro_f1", 0.0) or 0.0)


def _tp_recall(report: dict[str, Any]) -> float:
    agents = _agents(report)
    per_class = agents.get("per_class") or {}
    return float((per_class.get("TruePositive") or {}).get("recall", 0.0) or 0.0)


def promotion_gate(
    candidate: dict[str, Any],
    current_workflow: dict[str, Any],
    non_llm_baseline: dict[str, Any],
    *,
    required_macro_f1_delta: float = 0.03,
) -> dict[str, Any]:
    """Return the three explicit promotion checks and their measured values."""
    candidate_f1 = _macro_f1(candidate)
    current_f1 = _macro_f1(current_workflow)
    baseline_f1 = _macro_f1(non_llm_baseline)
    candidate_tp = _tp_recall(candidate)
    current_tp = _tp_recall(current_workflow)
    delta = candidate_f1 - current_f1

    checks = {
        "macro_f1_delta": {
            "passed": delta >= required_macro_f1_delta,
            "actual": round(delta, 4),
            "required": required_macro_f1_delta,
        },
        "non_llm_floor": {
            "passed": candidate_f1 >= baseline_f1,
            "actual": round(candidate_f1, 4),
            "required": round(baseline_f1, 4),
        },
        "true_positive_recall": {
            "passed": candidate_tp >= current_tp,
            "actual": round(candidate_tp, 4),
            "required": round(current_tp, 4),
        },
    }
    return {
        "passed": all(check["passed"] for check in checks.values()),
        "required_macro_f1_delta": required_macro_f1_delta,
        "candidate_macro_f1": round(candidate_f1, 4),
        "current_macro_f1": round(current_f1, 4),
        "baseline_macro_f1": round(baseline_f1, 4),
        "candidate_true_positive_recall": round(candidate_tp, 4),
        "current_true_positive_recall": round(current_tp, 4),
        "checks": checks,
    }
