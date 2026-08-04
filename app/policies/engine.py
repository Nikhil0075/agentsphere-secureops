"""Deterministic policy gate.

This is the control that constrains agent autonomy, and it is deliberately not an LLM. The
Verifier agent *reasons* about whether a recommendation holds up; this engine *decides* whether it
may proceed without a human. An agent cannot talk its way past a dictionary lookup, and that
distinction is the honest answer to "is this just an LLM wrapper?" (§12.3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.agents.schemas import (
    PolicyCheck,
    RemediationOutput,
    RiskLevel,
    TriageOutput,
    VerifierOutput,
)

CATALOGUE_PATH = Path(__file__).with_name("catalogue.yaml")

_RISK_ORDER = {RiskLevel.LOW.value: 0, RiskLevel.MEDIUM.value: 1, RiskLevel.HIGH.value: 2}


@lru_cache(maxsize=1)
def load_catalogue(path: str | Path = CATALOGUE_PATH) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    ids = [a["id"] for a in data["actions"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate action id in catalogue.yaml")
    for action in data["actions"]:
        if action["risk"] not in _RISK_ORDER:
            raise ValueError(f"{action['id']}: unknown risk level {action['risk']!r}")
    return data


def actions() -> list[dict[str, Any]]:
    return load_catalogue()["actions"]


def action_by_id(action_id: str) -> dict[str, Any] | None:
    return next((a for a in actions() if a["id"] == action_id), None)


def actions_for_label(label: str) -> list[dict[str, Any]]:
    return [a for a in actions() if label in a.get("applicable_labels", [])]


def catalogue_prompt_block() -> str:
    """The catalogue as the Remediation agent sees it — ids, risk levels and applicability."""
    lines = []
    for action in actions():
        lines.append(
            f"- {action['id']} (risk={action['risk']}): {action['name']}. "
            f"Applies to: {', '.join(action.get('applicable_labels', []))}. "
            f"Rollback: {action.get('rollback', 'n/a')}"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class GateDecision:
    """The outcome of the gate, and every check that produced it."""

    requires_approval: bool
    auto_approved: bool
    action_risk: str
    reasons: list[str] = field(default_factory=list)
    checks: list[PolicyCheck] = field(default_factory=list)

    def failed_policies(self) -> list[str]:
        return [c.policy_id for c in self.checks if not c.passed]


def evaluate(
    triage: TriageOutput,
    remediation: RemediationOutput,
    verifier: VerifierOutput | None = None,
    evidence_ids: list[str] | None = None,
) -> GateDecision:
    """Decide whether a recommendation may proceed without a human.

    The default is to require approval. Auto-approval has to be earned by satisfying every
    condition in ``gate.auto_approve``; anything unresolved falls back to a person.
    """
    catalogue = load_catalogue()
    auto = catalogue["gate"]["auto_approve"]
    force = catalogue["gate"]["force_human_approval"]

    action = action_by_id(remediation.recommended_action)
    # An unrecognised action is not automatically safe — it is unknown, which is worse.
    action_risk = action["risk"] if action else remediation.action_risk.value

    checks: list[PolicyCheck] = []
    reasons: list[str] = []

    # POL-003: the action must be applicable to the assigned label.
    applicable = bool(action) and triage.label.value in action.get("applicable_labels", [])
    checks.append(
        PolicyCheck(
            policy_id="POL-003",
            passed=applicable,
            detail=(
                f"{remediation.recommended_action} is applicable to {triage.label.value}"
                if applicable
                else f"{remediation.recommended_action!r} is not a catalogue action for "
                f"{triage.label.value}"
            ),
        )
    )
    if not applicable:
        reasons.append("recommended action is not applicable to the triage label")

    # POL-002: triage must cite evidence that is actually in the bundle.
    if evidence_ids is None:
        cited_ok = bool(triage.supporting_evidence_ids)
        detail = "evidence bundle unavailable; citation presence checked only"
    else:
        known = set(evidence_ids)
        unknown = [e for e in triage.supporting_evidence_ids if e not in known]
        cited_ok = bool(triage.supporting_evidence_ids) and not unknown
        detail = (
            "all cited evidence ids are present in the bundle"
            if cited_ok
            else f"cited evidence not in bundle: {unknown[:5]}"
        )
    checks.append(PolicyCheck(policy_id="POL-002", passed=cited_ok, detail=detail))
    if not cited_ok:
        reasons.append("triage cites evidence that is not in the bundle")

    # POL-004: a confidence floor applies at every risk level.
    confident = triage.confidence >= float(auto["min_confidence"])
    checks.append(
        PolicyCheck(
            policy_id="POL-004",
            passed=confident,
            detail=f"confidence {triage.confidence:.2f} vs floor {auto['min_confidence']:.2f}",
        )
    )
    if not confident:
        reasons.append(f"confidence {triage.confidence:.2f} is below the auto-approval floor")

    # POL-005: the Verifier can stop finalisation on its own.
    verifier_ok = verifier is not None and verifier.verdict.value == "accept"
    if verifier is None:
        verifier_detail = "no verifier verdict available"
    else:
        verifier_detail = f"verifier verdict is {verifier.verdict.value}"
    checks.append(
        PolicyCheck(policy_id="POL-005", passed=verifier_ok, detail=verifier_detail)
    )
    if not verifier_ok:
        reasons.append(verifier_detail)

    if verifier is not None and verifier.contradictions:
        reasons.append(f"verifier found {len(verifier.contradictions)} contradiction(s)")

    # POL-001: risk ceiling for autonomous action.
    risk_ok = _RISK_ORDER.get(action_risk, 2) <= _RISK_ORDER[auto["max_risk"]]
    checks.append(
        PolicyCheck(
            policy_id="POL-001",
            passed=risk_ok,
            detail=f"action risk {action_risk} vs auto ceiling {auto['max_risk']}",
        )
    )
    if not risk_ok:
        reasons.append(f"{action_risk}-risk action requires a named human approver")

    forced = (
        action_risk in force["risk_levels"]
        or (verifier is not None and verifier.verdict.value in force["verifier_verdicts"])
        or triage.confidence < float(force["below_confidence"])
    )
    no_contradictions = verifier is not None and not verifier.contradictions

    auto_approved = (
        not forced
        and risk_ok
        and confident
        and cited_ok
        and applicable
        and (verifier_ok or not auto["require_verifier_accept"])
        and (no_contradictions or not auto["require_no_contradictions"])
    )

    return GateDecision(
        requires_approval=not auto_approved,
        auto_approved=auto_approved,
        action_risk=action_risk,
        reasons=reasons if not auto_approved else [],
        checks=checks,
    )
