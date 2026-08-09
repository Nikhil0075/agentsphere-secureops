"""Risk scoring, the priority queue and the policy gate.

The gate tests matter most: they are the executable form of the claim that autonomy is bounded by
something deterministic rather than by a prompt.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.agents.schemas import (
    BaselinePrediction,
    RemediationOutput,
    RiskLevel,
    TriageLabel,
    TriageOutput,
    VerifierOutput,
)
from app.policies import engine, risk
from app.policies.queue import IncidentQueue, QueueItem

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


# --- risk scoring ---------------------------------------------------------------------------

def test_weights_sum_to_one():
    assert abs(sum(risk.load_config()["weights"].values()) - 1.0) < 1e-9


def test_score_is_bounded_for_extreme_inputs():
    quiet = {"max_suspicion_level": "Benign", "alert_count": 0, "first_seen": ""}
    loud = {
        "max_suspicion_level": "Malicious",
        "max_last_verdict": "Malicious",
        "alert_count": 500,
        "distinct_device_count": 50,
        "threat_families": "LockBit;Emotet;Qakbot",
        "first_seen": (NOW - timedelta(days=30)).isoformat(),
    }
    for incident in (quiet, loud):
        assert 0.0 <= risk.score(incident, baseline_confidence=0.5, now=NOW) <= 1.0
    assert risk.score(loud, baseline_confidence=0.9, now=NOW) > risk.score(
        quiet, baseline_confidence=0.1, now=NOW
    )


def test_every_component_is_normalised_before_weighting():
    """The §8.5 failure mode: a raw count swamping a 0-1 confidence."""
    breakdown = risk.explain(
        {"alert_count": 10_000, "max_suspicion_level": "Benign", "first_seen": ""},
        baseline_confidence=0.5,
        now=NOW,
    )
    for name, value in breakdown.components.items():
        assert 0.0 <= value <= 1.0, f"{name} escaped normalisation: {value}"


def test_counts_saturate_rather_than_scale_linearly():
    base = {"max_suspicion_level": "Suspicious", "first_seen": ""}
    ten = risk.score({**base, "alert_count": 10}, baseline_confidence=0.5, now=NOW)
    forty = risk.score({**base, "alert_count": 40}, baseline_confidence=0.5, now=NOW)
    assert forty >= ten
    assert forty - ten < 0.05, "alert count is scaling close to linearly"


def test_missing_baseline_uses_a_neutral_prior():
    incident = {"max_suspicion_level": "Suspicious", "alert_count": 2, "first_seen": ""}
    assert risk.explain(incident, now=NOW).components["model_confidence"] == 0.5


def test_breakdown_is_explainable():
    breakdown = risk.explain(
        {"max_suspicion_level": "Malicious", "alert_count": 5, "first_seen": ""},
        baseline_confidence=0.9,
        now=NOW,
    )
    assert abs(sum(breakdown.weighted.values()) - breakdown.score) < 1e-6
    assert len(breakdown.top_drivers(3)) == 3


def test_sla_urgency_grows_with_age():
    old = {"first_seen": (NOW - timedelta(hours=48)).isoformat()}
    new = {"first_seen": (NOW - timedelta(minutes=5)).isoformat()}
    assert risk.sla_component(old, now=NOW) == 1.0
    assert risk.sla_component(new, now=NOW) < 0.1


# --- priority queue -------------------------------------------------------------------------

def test_queue_pops_in_descending_risk():
    q = IncidentQueue(
        [
            QueueItem("INC-a", 0.20),
            QueueItem("INC-b", 0.90),
            QueueItem("INC-c", 0.55),
        ]
    )
    assert [item.incident_id for item in q.drain()] == ["INC-b", "INC-c", "INC-a"]


def test_identical_scores_do_not_raise_type_error():
    """§8.1: a tie must fall through to a comparable element, not blow up."""
    q = IncidentQueue([QueueItem(f"INC-{i}", 0.5, severity=1.0) for i in range(50)])
    order = [item.incident_id for item in q.drain()]
    assert order == sorted(order)


def test_ties_break_on_severity_then_id():
    q = IncidentQueue(
        [
            QueueItem("INC-b", 0.5, severity=1),
            QueueItem("INC-a", 0.5, severity=9),
        ]
    )
    assert [i.incident_id for i in q.drain()] == ["INC-a", "INC-b"]


def test_peek_does_not_consume():
    q = IncidentQueue([QueueItem("INC-a", 0.1), QueueItem("INC-b", 0.9)])
    assert q.peek().incident_id == "INC-b"
    assert len(q) == 2


def test_top_k_matches_a_full_sort():
    items = [QueueItem(f"INC-{i:03d}", (i * 37 % 100) / 100) for i in range(200)]
    q = IncidentQueue(items)
    expected = [i.incident_id for i in sorted(items, key=lambda x: x.sort_key())[:5]]
    assert [i.incident_id for i in q.top_k(5)] == expected


def test_duplicate_incident_is_rejected():
    q = IncidentQueue([QueueItem("INC-a", 0.5)])
    with pytest.raises(ValueError):
        q.push(QueueItem("INC-a", 0.9))


def test_empty_queue_raises_rather_than_returning_none():
    q = IncidentQueue()
    with pytest.raises(IndexError):
        q.pop()
    with pytest.raises(IndexError):
        q.peek()
    assert q.top_k(3) == []


# --- policy gate ----------------------------------------------------------------------------

def _triage(label=TriageLabel.FALSE_POSITIVE, confidence=0.95, ids=("EVD-1",)):
    return TriageOutput(
        label=label,
        confidence=confidence,
        rationale="rationale",
        supporting_evidence_ids=list(ids),
    )


def _remediation(action="close_as_false_positive", level=RiskLevel.LOW):
    return RemediationOutput(
        recommended_action=action,
        action_risk=level,
        rollback_plan="reopen",
        justification="justification",
    )


def _verifier(verdict="accept", contradictions=()):
    return VerifierOutput(
        verdict=verdict,
        contradictions=list(contradictions),
        policy_checks=[],
        escalation_required=verdict != "accept",
        reasoning="reasoning",
    )


def test_catalogue_has_both_required_scenarios():
    """§7.1: at least one safe auto-action and one mandatory-approval action."""
    risks = {a["risk"] for a in engine.actions()}
    assert "low" in risks and "high" in risks


def test_low_risk_confident_accepted_auto_approves():
    decision = engine.evaluate(_triage(), _remediation(), _verifier(), evidence_ids=["EVD-1"])
    assert decision.auto_approved is True
    assert decision.requires_approval is False


def test_high_risk_always_requires_a_human():
    decision = engine.evaluate(
        _triage(label=TriageLabel.TRUE_POSITIVE, confidence=0.99),
        _remediation("isolate_device", RiskLevel.HIGH),
        _verifier(),
        evidence_ids=["EVD-1"],
    )
    assert decision.requires_approval is True
    assert "POL-001" in decision.failed_policies()


def test_low_confidence_blocks_even_a_low_risk_action():
    decision = engine.evaluate(
        _triage(confidence=0.4), _remediation(), _verifier(), evidence_ids=["EVD-1"]
    )
    assert decision.requires_approval is True
    assert "POL-004" in decision.failed_policies()


def test_high_confidence_baseline_agreement_allows_bounded_low_risk_path():
    baseline = BaselinePrediction(
        label=TriageLabel.FALSE_POSITIVE,
        confidence=0.95,
        model_name="calibrated-baseline",
    )
    decision = engine.evaluate(
        _triage(confidence=0.58),
        _remediation(),
        _verifier(),
        evidence_ids=["EVD-1"],
        baseline=baseline,
    )
    assert decision.auto_approved
    assert "dual agreement" in next(
        check.detail for check in decision.checks if check.policy_id == "POL-004"
    )


def test_dual_agreement_never_overrides_label_disagreement():
    baseline = BaselinePrediction(
        label=TriageLabel.TRUE_POSITIVE,
        confidence=0.99,
        model_name="calibrated-baseline",
    )
    decision = engine.evaluate(
        _triage(confidence=0.72),
        _remediation(),
        _verifier(),
        evidence_ids=["EVD-1"],
        baseline=baseline,
    )
    assert decision.requires_approval
    assert "POL-004" in decision.failed_policies()


def test_dual_agreement_is_never_an_autonomous_true_positive_path():
    baseline = BaselinePrediction(
        label=TriageLabel.TRUE_POSITIVE,
        confidence=0.99,
        model_name="calibrated-baseline",
    )
    decision = engine.evaluate(
        _triage(label=TriageLabel.TRUE_POSITIVE, confidence=0.72),
        _remediation("request_user_verification", RiskLevel.LOW),
        _verifier(),
        evidence_ids=["EVD-1"],
        baseline=baseline,
    )
    assert decision.requires_approval
    assert "POL-004" in decision.failed_policies()


def test_any_degraded_agent_blocks_autonomy():
    decision = engine.evaluate(
        _triage(),
        _remediation(),
        _verifier(),
        evidence_ids=["EVD-1"],
        degraded_agents=["verifier"],
    )
    assert decision.requires_approval
    assert "POL-006" in decision.failed_policies()


def test_verifier_rejection_blocks_finalisation():
    decision = engine.evaluate(
        _triage(), _remediation(), _verifier("reject", ["contradicted by evidence"]),
        evidence_ids=["EVD-1"],
    )
    assert decision.requires_approval is True
    assert "POL-005" in decision.failed_policies()


def test_uncited_evidence_blocks():
    decision = engine.evaluate(
        _triage(ids=("EVD-does-not-exist",)),
        _remediation(),
        _verifier(),
        evidence_ids=["EVD-1"],
    )
    assert decision.requires_approval is True
    assert "POL-002" in decision.failed_policies()


def test_action_must_be_applicable_to_the_label():
    decision = engine.evaluate(
        _triage(label=TriageLabel.FALSE_POSITIVE),
        _remediation("isolate_device", RiskLevel.HIGH),
        _verifier(),
        evidence_ids=["EVD-1"],
    )
    assert "POL-003" in decision.failed_policies()


def test_unknown_action_is_treated_as_high_risk_not_as_safe():
    decision = engine.evaluate(
        _triage(), _remediation("delete_everything", RiskLevel.LOW), _verifier(),
        evidence_ids=["EVD-1"],
    )
    assert decision.requires_approval is True


def test_missing_verifier_blocks_auto_approval():
    decision = engine.evaluate(_triage(), _remediation(), None, evidence_ids=["EVD-1"])
    assert decision.requires_approval is True


def test_every_decision_carries_its_checks():
    decision = engine.evaluate(_triage(), _remediation(), _verifier(), evidence_ids=["EVD-1"])
    assert {c.policy_id for c in decision.checks} == {
        "POL-001",
        "POL-002",
        "POL-003",
        "POL-004",
        "POL-005",
        "POL-006",
    }
