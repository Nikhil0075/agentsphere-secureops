"""Remediation, Verifier and the policy gate.

The Day 4 exit criterion — "the Verifier rejects at least one deliberately inconsistent
recommendation" — is `test_conflict_scenario_is_rejected`. Everything else supports it.
"""

from __future__ import annotations

import pandas as pd
import pytest

from app.agents.llm import DeterministicClient, FailingClient
from app.agents.remediation import RemediationAgent
from app.agents.schemas import (
    RiskLevel,
    TriageLabel,
    VerifierVerdict,
    WorkflowState,
)
from app.agents.verifier import VerifierAgent
from app.data import fixture
from app.data import incidents as incidents_mod
from app.orchestration.context import IncidentContext
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow
from app.policies import engine
from tests.fixtures import scenarios


@pytest.fixture(scope="module")
def dataset():
    evidence = fixture.generate(n_incidents=30)
    incidents = incidents_mod.aggregate(evidence)
    incidents["summary"] = "summary for testing"
    return evidence, incidents


@pytest.fixture
def context(dataset):
    evidence, incidents = dataset
    row = incidents.iloc[0]
    return IncidentContext.from_incident(row, incidents_mod.evidence_for(evidence, row["incident_id"]))


def _verify(state: WorkflowState, context: IncidentContext):
    agent = VerifierAgent(DeterministicClient())
    return agent.run(state, context=context)[0]


def _gate(state: WorkflowState):
    return engine.evaluate(
        triage=state.triage,
        remediation=state.remediation,
        verifier=state.verifier,
        evidence_ids=state.correlation.evidence_bundle,
    )


# --- the exit criterion --------------------------------------------------------------------

def test_conflict_scenario_is_rejected(context):
    """§12.2 scenario 3, and the Day 4 exit criterion.

    A high-risk action on a FalsePositive, citing evidence outside the bundle, asserted at 0.94
    confidence over unresolved gaps. The Verifier must reject it.
    """
    state = scenarios.conflict()
    verdict = _verify(state, context)

    assert verdict.verdict is VerifierVerdict.REJECT
    assert verdict.escalation_required
    assert len(verdict.contradictions) >= 2
    assert any(not c.passed for c in verdict.policy_checks)


def test_conflict_rejection_names_the_specific_faults(context):
    """A rejection with no reason is not auditable."""
    verdict = _verify(scenarios.conflict(), context)
    joined = " ".join(verdict.contradictions).lower()
    assert "not in the correlation bundle" in joined
    assert "disable_account" in joined or "not applicable" in joined


def test_a_rejected_recommendation_still_blocks_at_the_gate(context):
    state = scenarios.conflict()
    state.verifier = _verify(state, context)
    gate = _gate(state)

    assert gate.requires_approval
    assert not gate.auto_approved
    assert "POL-005" in gate.failed_policies()  # verifier verdict blocks finalisation


def test_the_failed_proposal_is_still_recorded(context):
    """§12.2: 'the failed proposal is recorded anyway'. A discarded rejection is a lost audit."""
    state = scenarios.conflict()
    state.verifier = _verify(state, context)
    assert state.remediation is not None
    assert state.remediation.recommended_action == "disable_account"
    assert state.verifier.verdict is VerifierVerdict.REJECT


# --- the other two scenarios ----------------------------------------------------------------

def test_true_positive_scenario_is_accepted_but_still_needs_a_human(context):
    """The chain is sound; the action is high-risk. Both facts must survive independently."""
    state = scenarios.true_positive()
    state.verifier = _verify(state, context)
    gate = _gate(state)

    assert state.verifier.verdict is VerifierVerdict.ACCEPT
    assert gate.requires_approval, "a high-risk action must never auto-approve"
    assert "POL-001" in gate.failed_policies()


def test_false_positive_scenario_takes_no_invasive_action(context):
    state = scenarios.false_positive()
    state.verifier = _verify(state, context)
    gate = _gate(state)

    assert state.verifier.verdict is VerifierVerdict.ACCEPT
    assert state.remediation.action_risk is RiskLevel.LOW
    assert gate.auto_approved, "a well-evidenced low-risk closure is the auto-approve path"
    assert not gate.requires_approval


# --- verifier checks, individually ------------------------------------------------------------

def test_evidence_outside_the_bundle_is_a_hard_failure(context):
    state = scenarios.true_positive()
    state.triage = state.triage.model_copy(
        update={"supporting_evidence_ids": ["EVD-not-in-bundle"]}
    )
    assert _verify(state, context).verdict is VerifierVerdict.REJECT


def test_an_off_catalogue_action_is_rejected(context):
    """An unrecognised action is unknown, which is worse than high-risk, not better."""
    state = scenarios.true_positive()
    state.remediation = state.remediation.model_copy(
        update={"recommended_action": "launch_counterattack"}
    )
    assert _verify(state, context).verdict is VerifierVerdict.REJECT


def test_high_confidence_over_substantial_gaps_is_flagged(context):
    from app.agents.verifier import GAP_TOLERANCE

    state = scenarios.true_positive()
    state.correlation = state.correlation.model_copy(
        update={"missing_information": [f"gap {i}" for i in range(GAP_TOLERANCE + 2)]}
    )
    verdict = _verify(state, context)
    assert verdict.verdict is not VerifierVerdict.ACCEPT
    assert any("gap" in c.lower() for c in verdict.contradictions)


def test_a_few_gaps_are_tolerated(context):
    """Calibration guard. A couple of genuine gaps is the dataset speaking, not the chain
    overreaching. An uncalibrated version of this check rejected 40 of 40 real incidents.

    This tolerance is only meaningful because Correlation stopped manufacturing gaps — see
    ``test_absent_entity_types_are_not_reported_as_gaps``. While an absent entity type counted as
    missing information, the mean incident carried 5.26 gaps against a tolerance of 3, so the
    check above fired on almost everything and the escalation it caused looked like caution."""
    from app.agents.verifier import GAP_TOLERANCE

    state = scenarios.true_positive()
    state.correlation = state.correlation.model_copy(
        update={"missing_information": [f"gap {i}" for i in range(GAP_TOLERANCE)]}
    )
    assert _verify(state, context).verdict is VerifierVerdict.ACCEPT


def test_a_degraded_agent_prevents_a_clean_accept(context):
    """Part of the chain was not reasoned. That is worth escalating, not hiding."""
    from app.agents.schemas import AgentRunRecord

    state = scenarios.true_positive()
    state.runs.append(
        AgentRunRecord(agent="investigation", sequence=3, status="fallback", attempts=2)
    )
    assert _verify(state, context).verdict is VerifierVerdict.ESCALATE


def test_baseline_disagreement_is_surfaced(context):
    from app.agents.schemas import BaselinePrediction

    state = scenarios.true_positive()
    state.baseline = BaselinePrediction(
        label=TriageLabel.FALSE_POSITIVE, confidence=0.88, model_name="stub"
    )
    verdict = _verify(state, context)
    assert any("baseline" in c.lower() for c in verdict.contradictions)


def test_verifier_reports_every_check_it_ran(context):
    """The checks are the audit record; a verdict with no checks is unreviewable."""
    verdict = _verify(scenarios.true_positive(), context)
    ids = {c.policy_id for c in verdict.policy_checks}
    assert {"VER-001", "VER-002", "VER-003", "VER-004", "VER-005", "VER-006", "VER-007"} <= ids


# --- reconciliation: structural checks bound the model, on every backend ----------------------

def _model_verifier(payload: dict):
    """A verifier agent whose 'model' returns exactly the payload given."""
    from app.agents.llm import FailingClient

    return VerifierAgent(FailingClient(failures=0, payload=payload))


def _semantic_checks(*failed: str) -> list[dict]:
    return [
        {
            "policy_id": policy_id,
            "passed": policy_id not in failed,
            "detail": "material conflict found" if policy_id in failed else "check passed",
        }
        for policy_id in ("SEM-001", "SEM-002", "SEM-003", "SEM-004")
    ]


def _llm_output(verdict: str, checks: list[dict] | None = None, contradictions=()) -> dict:
    return {
        "verdict": verdict,
        "contradictions": list(contradictions),
        "policy_checks": _semantic_checks() if checks is None else checks,
        "escalation_required": verdict != "accept",
        "reasoning": "model reasoning",
    }


def test_structural_checks_run_even_when_a_model_produced_the_output(context):
    """The defect this fixes: on the live backend the seven VER checks never ran at all."""
    state = scenarios.true_positive()
    output = _model_verifier(_llm_output("accept")).run(state, context=context)[0]
    ids = {c.policy_id for c in output.policy_checks}
    assert {"VER-001", "VER-002", "VER-003"} <= ids


def test_a_model_cannot_accept_a_structurally_broken_chain(context):
    """The conflict scenario must be rejected no matter how happy the model is with it."""
    state = scenarios.conflict()
    output = _model_verifier(_llm_output("accept")).run(state, context=context)[0]
    assert output.verdict is VerifierVerdict.REJECT


def test_a_model_cannot_reject_or_escalate_on_taste_alone(context):
    """A vague raw verdict cannot become a hidden policy when every named check passed."""
    state = scenarios.true_positive()
    output, record = _model_verifier(
        _llm_output("reject", contradictions=["I am uneasy about this"])
    ).run(state, context=context)
    assert record.status == "fallback"
    assert output.verdict is VerifierVerdict.ACCEPT
    assert output.contradictions == []


def test_the_models_own_checks_are_kept_but_marked_as_its_own(context):
    """Its reasoning stays auditable; it just cannot masquerade as a system policy id."""
    state = scenarios.true_positive()
    output = _model_verifier(
        _llm_output(
            "accept",
            checks=_semantic_checks()
            + [{"policy_id": "MadeUpPolicy", "passed": True, "detail": "looks fine"}],
        )
    ).run(state, context=context)[0]
    ids = {c.policy_id for c in output.policy_checks}
    assert "LLM-MadeUpPolicy" in ids
    assert "MadeUpPolicy" not in ids


def test_a_failed_material_semantic_check_is_respected(context):
    state = scenarios.true_positive()
    output = _model_verifier(
        _llm_output(
            "escalate",
            checks=_semantic_checks("SEM-004"),
        )
    ).run(state, context=context)[0]
    assert output.verdict is VerifierVerdict.ESCALATE
    assert output.escalation_required
    assert output.contradictions == []


def test_an_escalation_concern_is_not_forced_to_masquerade_as_a_contradiction(context):
    state = scenarios.true_positive()
    output, record = _model_verifier(
        _llm_output(
            "escalate",
            checks=_semantic_checks("SEM-003"),
        )
    ).run(state, context=context)

    assert record.status == "ok"
    assert output.verdict is VerifierVerdict.ESCALATE
    assert output.contradictions == []


def test_direct_evidence_contradiction_can_reject_a_structurally_valid_chain(context):
    state = scenarios.true_positive()
    output = _model_verifier(
        _llm_output(
            "reject",
            checks=_semantic_checks("SEM-001"),
            contradictions=["cited evidence directly contradicts the rationale"],
        )
    ).run(state, context=context)[0]
    assert output.verdict is VerifierVerdict.REJECT


def test_missing_semantic_rubric_retries_then_degrades_to_structural_verification(context):
    state = scenarios.true_positive()
    agent = _model_verifier(
        _llm_output(
            "escalate",
            checks=[{"policy_id": "confidence", "passed": False, "detail": "uncertain"}],
        )
    )
    output, record = agent.run(state, context=context)
    assert record.status == "fallback"
    assert record.attempts == 2
    assert output.verdict is VerifierVerdict.ACCEPT


def test_structural_checks_are_not_listed_twice(context):
    """On the deterministic backend the output already is the structural output; re-listing it
    as LLM-VER-001…007 beside the originals makes the audit panel read as confused."""
    state = scenarios.true_positive()
    output = VerifierAgent(DeterministicClient()).run(state, context=context)[0]
    ids = [c.policy_id for c in output.policy_checks]

    assert len(ids) == len(set(ids)), f"duplicate policy ids: {ids}"
    assert not any(i.startswith("LLM-VER-") for i in ids)


def test_model_reasoning_is_preserved_alongside_the_structural_verdict(context):
    state = scenarios.true_positive()
    output = _model_verifier(_llm_output("accept")).run(state, context=context)[0]
    assert "model reasoning" in output.reasoning
    assert "structural checks passed" in output.reasoning


# --- remediation -------------------------------------------------------------------------------

def test_remediation_only_proposes_catalogue_actions(context):
    catalogue = {a["id"] for a in engine.actions()}
    for build in scenarios.SCENARIOS.values():
        state = build()
        agent = RemediationAgent(DeterministicClient())
        output = agent.run(state, context=context)[0]
        assert output.recommended_action in catalogue


def test_remediation_matches_the_catalogue_risk_level(context):
    state = scenarios.true_positive()
    output = RemediationAgent(DeterministicClient()).run(state, context=context)[0]
    action = engine.action_by_id(output.recommended_action)
    assert output.action_risk.value == action["risk"]


def test_a_false_positive_never_gets_an_invasive_action(context):
    state = scenarios.false_positive()
    output = RemediationAgent(DeterministicClient()).run(state, context=context)[0]
    assert output.action_risk is RiskLevel.LOW


def test_low_confidence_produces_a_weaker_action_not_a_stronger_one(context):
    """The instinct to escalate when unsure is wrong: uncertainty justifies watching, not
    disabling somebody's account."""
    confident = scenarios.true_positive()
    unsure = scenarios.true_positive()
    unsure.triage = unsure.triage.model_copy(update={"confidence": 0.45})
    unsure.correlation = unsure.correlation.model_copy(
        update={"missing_information": ["telemetry gap"]}
    )

    agent = RemediationAgent(DeterministicClient())
    risk = {"low": 0, "medium": 1, "high": 2}
    strong = agent.run(confident, context=context)[0]
    weak = agent.run(unsure, context=context)[0]
    assert risk[weak.action_risk.value] < risk[strong.action_risk.value]


def test_remediation_states_that_the_action_is_simulated(context):
    output = RemediationAgent(DeterministicClient()).run(
        scenarios.true_positive(), context=context
    )[0]
    assert "simulated" in output.justification.lower()


# --- the full six-agent chain ------------------------------------------------------------------

def test_the_chain_runs_all_six_agents(dataset):
    evidence, incidents = dataset
    row = incidents.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    result = Workflow(client=DeterministicClient()).run(row, rows)

    assert len(AGENT_SEQUENCE) == 6
    assert [r.agent for r in result.state.runs] == list(AGENT_SEQUENCE)
    assert result.state.remediation is not None
    assert result.state.verifier is not None


def test_the_gate_runs_after_the_verifier(dataset):
    evidence, incidents = dataset
    row = incidents.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    result = Workflow(client=DeterministicClient()).run(row, rows)

    assert result.gate is not None
    assert result.state.requires_approval == result.gate.requires_approval
    assert result.gate.checks


def test_a_totally_failed_chain_defaults_to_requiring_approval(dataset):
    """Default deny. If the chain could not reason, nothing gets auto-approved."""
    evidence, incidents = dataset
    row = incidents.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    result = Workflow(client=FailingClient(failures=99)).run(row, rows)

    assert result.state.requires_approval
    assert not (result.gate and result.gate.auto_approved)


# --- correlation gap reporting ------------------------------------------------------------------


def _gaps(entity_counts, *, timeline=(1,), clusters=({"linking_entities": ["account:a"]},)):
    from app.agents.correlation import CorrelationAgent

    agent = CorrelationAgent.__new__(CorrelationAgent)
    return agent._missing(
        {
            "entity_counts": dict(entity_counts),
            "timeline": list(timeline),
            "clusters": [dict(c) for c in clusters],
        }
    )


def test_absent_entity_types_are_not_reported_as_gaps():
    """The single largest source of escalation in the chain, and it was self-inflicted.

    Correlation emitted one gap per *absent* entity type, checking all seven against every
    incident. Measured on the 5,000-incident corpus that is a mean of 5.26 gaps each: 53.2% of
    incidents carry one entity type or none, and exactly 5 carry all seven. GUIDE is
    evidence-level, so a row holds only the fields its source product emits — a mailbox alert has
    no file hash and never will.

    Because ``missing_information`` is rendered into four downstream prompts and the Verifier
    flags high confidence above GAP_TOLERANCE=3 gaps, a normally-shaped incident arrived at the
    gate already described as full of holes.
    """
    gaps = _gaps({"account": 4, "ip": 2})
    assert gaps == [], gaps
    assert not any("no url" in g or "no filehash" in g or "no device" in g for g in gaps)


def test_having_nothing_to_pivot_on_is_still_a_gap():
    """The distinction the old check could not draw: sparse is normal, empty is not."""
    gaps = _gaps({})
    assert len(gaps) == 1
    assert "no entities of any type" in gaps[0]


def test_a_single_entity_type_is_reported_as_uncorroborated():
    gaps = _gaps({"account": 9})
    assert len(gaps) == 1
    assert "one type (account)" in gaps[0]


def test_real_structural_gaps_survive_and_stay_within_tolerance():
    from app.agents.verifier import GAP_TOLERANCE

    gaps = _gaps({}, timeline=(), clusters=())
    assert any("chronology" in g for g in gaps)
    assert any("did not cluster" in g for g in gaps)
    # Even the worst case must not trip the Verifier's tolerance on its own.
    assert len(gaps) <= GAP_TOLERANCE


# --- prompt self-consistency ---------------------------------------------------------------------
# Three renderings that made the chain contradict itself, each measured on the flagship demo case.


def test_opaque_numeric_ids_are_named_as_ids():
    """GUIDE anonymises categorical text into integers.

    Rendered plainly, ``alert_title`` produced "Distinct alert title (1): 1." two lines under
    "26 alert(s)" — a label of 1 with a value of 1. The Verifier quoted it back as "Alerts: 1",
    called the incident accounting inconsistent, and escalated. It was reading our formatting,
    not the data.
    """
    import pandas as pd

    from app.data.summarize import build_incident_summary

    summary = build_incident_summary(
        {"incident_id": "INC-1", "alert_count": 26, "evidence_count": 26, "top_detector": "1"},
        pd.DataFrame({"alert_title": ["1", "1"]}),
    )
    assert "Detector: 1 (opaque numeric id, not a name)." in summary
    assert "opaque numeric id(s), not names" in summary


def test_a_real_name_is_not_labelled_as_an_id():
    import pandas as pd

    from app.data.summarize import build_incident_summary

    summary = build_incident_summary(
        {"incident_id": "INC-1", "top_detector": "Defender for Endpoint"},
        pd.DataFrame({"alert_title": ["Suspicious sign-in"]}),
    )
    assert "opaque numeric" not in summary


def test_a_capped_chronology_says_that_it_is_capped():
    """A silent cap is indistinguishable from missing data to whoever reads the prompt."""
    from app.agents.correlation import CorrelationAgent

    agent = CorrelationAgent.__new__(CorrelationAgent)
    prompt = agent.build_prompt(
        {
            "incident_id": "INC-1",
            "clusters": [],
            "timeline": [
                {"timestamp": f"t{i}", "evidence_id": f"EVD-{i}", "description": "x"}
                for i in range(26)
            ],
            "correlation_summary": {"alerts": 26, "clusters": 18},
            "entity_counts": {"account": 3},
        }
    )
    assert "14 further dated event(s) not shown here" in prompt
    assert "display limit, not missing data" in prompt


def test_the_verifier_can_check_the_cluster_count_it_is_told_about():
    """Correlation asserts "N alerts across M clusters"; the Verifier used to have no way to
    confirm M and recorded it as unsupported — a contradiction created by withholding, not by
    disagreement. The clustering is deterministic and checkable, so show it."""
    from app.agents.verifier import VerifierAgent

    agent = VerifierAgent.__new__(VerifierAgent)
    prompt = agent.build_prompt(
        {
            "incident_id": "INC-1",
            "summary": "s",
            "evidence_block": "b",
            "severity": 0.5,
            "label": "TruePositive",
            "confidence": 0.9,
            "rationale": "r",
            "bundle": ["EVD-1"],
            "incident_evidence_count": 26,
            "cited": ["EVD-1"],
            "missing": [],
            "correlation_summary": {"alerts": 26, "clusters": 18},
            "similar_count": 1,
            "mitre_count": 1,
            "action": "monitor_and_watchlist",
            "action_risk": "low",
            "action_in_catalogue": True,
            "applicable_labels": ["TruePositive"],
            "baseline_label": "TruePositive",
            "baseline_confidence": 0.7,
            "degraded": [],
            "degraded_agents": [],
        }
    )
    assert "26 alert(s) collapsed into 18 cluster(s)" in prompt
    # The evidence block is bundle-scoped; saying so stops "26 claimed, 1 shown" reading as
    # an inconsistency rather than as a scope.
    assert "correlation bundle (1 of 26 item(s) on this incident)" in prompt
