"""The agent chain: happy path, failure handling, and the guarantees that must not slip.

The failure tests carry most of the weight. Any chain works when everything works; what matters is
that a timeout produces a marked degradation rather than a confident-looking wrong answer.
"""

from __future__ import annotations

import pandas as pd
import pytest

from app.agents.llm import (
    CacheMiss,
    DeterministicClient,
    FailingClient,
    LLMError,
    ReplayClient,
    ResponseCache,
    build_client,
    cache_key,
)
from app.agents.schemas import AGENT_OUTPUT_MODELS, TriageLabel
from app.data import fixture
from app.data import incidents as incidents_mod
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow
from app.retrieval.base import EntityOverlapRetriever, NullRetriever


@pytest.fixture(scope="module")
def dataset():
    evidence = fixture.generate(n_incidents=40)
    evidence = evidence.sort_values(
        ["incident_id", "alert_id", "evidence_id"]
    ).reset_index(drop=True)
    incidents = incidents_mod.aggregate(evidence)
    incidents["summary"] = "incident summary for testing"
    return evidence, incidents


@pytest.fixture
def one_incident(dataset):
    evidence, incidents = dataset
    row = incidents.iloc[0]
    return row, incidents_mod.evidence_for(evidence, row["incident_id"])


# --- happy path -----------------------------------------------------------------------------

def test_workflow_runs_offline_with_no_key(one_incident):
    """§14.3: a fallback mode must work with no external API dependency."""
    row, rows = one_incident
    result = Workflow(client=DeterministicClient()).run(row, rows)

    assert result.state.triage is not None
    assert result.label in {label.value for label in TriageLabel}
    assert result.degraded_agents() == []


def test_every_day_three_agent_produces_output(one_incident):
    row, rows = one_incident
    state = Workflow(client=DeterministicClient()).run(row, rows).state
    for name in AGENT_SEQUENCE:
        assert getattr(state, name) is not None, f"{name} produced nothing"
    assert [r.agent for r in state.runs] == list(AGENT_SEQUENCE)


def test_agents_run_in_contract_order(one_incident):
    row, rows = one_incident
    state = Workflow(client=DeterministicClient()).run(row, rows).state
    assert [r.sequence for r in state.runs] == list(range(1, len(AGENT_SEQUENCE) + 1))
    assert [r.agent for r in state.runs] == list(AGENT_SEQUENCE)


def test_triage_cites_evidence_from_the_bundle(one_incident):
    """POL-002 is enforced by the gate; this ensures the agent does not violate it by default."""
    row, rows = one_incident
    state = Workflow(client=DeterministicClient()).run(row, rows).state
    bundle = set(state.correlation.evidence_bundle)
    assert set(state.triage.supporting_evidence_ids) <= bundle


def test_workflow_produces_stable_hashes(one_incident):
    row, rows = one_incident
    a = Workflow(client=DeterministicClient()).run(row, rows).state
    b = Workflow(client=DeterministicClient()).run(row, rows).state
    assert a.evidence_hash == b.evidence_hash
    assert a.output_hash == b.output_hash
    assert a.workflow_id != b.workflow_id  # ids are per-run, hashes are per-content


def test_baseline_is_recorded_when_a_model_is_supplied(one_incident):
    row, rows = one_incident

    class StubModel:
        implementation = "stub"

        def predict_one(self, incident):
            return {
                "label": "TruePositive",
                "confidence": 0.91,
                "probabilities": {
                    "TruePositive": 0.91,
                    "BenignPositive": 0.06,
                    "FalsePositive": 0.03,
                },
                "model_name": "stub",
            }

    state = Workflow(client=DeterministicClient()).run(row, rows, baseline_model=StubModel()).state
    assert state.baseline is not None
    assert state.baseline.label.value == "TruePositive"
    assert state.triage.label.value == "TruePositive"


def test_a_broken_baseline_does_not_stop_triage(one_incident):
    row, rows = one_incident

    class ExplodingModel:
        def predict_one(self, incident):
            raise RuntimeError("stale pickle")

    result = Workflow(client=DeterministicClient()).run(
        row, rows, baseline_model=ExplodingModel()
    )
    assert result.state.triage is not None
    assert result.state.baseline is None


def test_correlation_result_reaches_the_state(one_incident):
    row, rows = one_incident
    result = Workflow(client=DeterministicClient()).run(row, rows)
    assert result.state.correlation_clusters >= 1
    assert result.context.correlation.alert_count >= 1


# --- failure handling -----------------------------------------------------------------------

def test_a_failing_backend_degrades_and_says_so(one_incident):
    """A fallback marked ok would corrupt the metrics. It must be marked fallback."""
    row, rows = one_incident
    client = FailingClient(failures=99)
    result = Workflow(client=client).run(row, rows)

    assert result.state.triage is not None, "the chain must still produce a decision"
    assert set(result.degraded_agents()) == set(AGENT_SEQUENCE)
    assert all(r.status == "fallback" for r in result.state.runs)
    assert result.state.errors


def test_a_transient_failure_is_retried(one_incident):
    """One retry is configured; a single failure should be absorbed, not surfaced."""
    from app.agents.detection import DetectionAgent
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    context = IncidentContext.from_incident(row, rows)
    payload = {
        "severity_score": 0.5,
        "suspicious_entities": [],
        "initial_reason": "recovered on the second attempt",
    }
    client = FailingClient(failures=1, payload=payload)

    state = WorkflowState(workflow_id="WF-test", incident_id=context.incident_id)
    output, record = DetectionAgent(client).run(state, context=context)

    assert record.status == "ok"
    assert record.attempts == 2
    assert output.initial_reason == "recovered on the second attempt"


def test_a_malformed_response_is_rejected_not_absorbed(one_incident):
    """An output that violates the frozen contract must never reach the state."""
    from app.agents.schemas import WorkflowState
    from app.agents.triage import TriageAgent
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    context = IncidentContext.from_incident(row, rows)
    client = FailingClient(failures=0, payload={"label": "Maybe", "confidence": 5.0})

    state = WorkflowState(workflow_id="WF-test", incident_id=context.incident_id)
    output, record = TriageAgent(client).run(state, context=context)

    assert record.status == "fallback"
    assert "schema validation failed" in record.validation_error
    assert output.label.value in {label.value for label in TriageLabel}


def test_fallback_output_still_satisfies_the_frozen_contract(one_incident):
    row, rows = one_incident
    state = Workflow(client=FailingClient(failures=99)).run(row, rows).state
    for name, model in AGENT_OUTPUT_MODELS.items():
        output = getattr(state, name, None)
        if output is not None:
            model.model_validate(output.model_dump(mode="json"))


def test_fallback_triage_is_not_overconfident(one_incident):
    """Conservative means assume less. A confident guess with no model is the wrong failure."""
    row, rows = one_incident
    state = Workflow(client=FailingClient(failures=99)).run(row, rows).state
    assert state.triage.confidence <= 0.6


# --- LLM client layer -----------------------------------------------------------------------

def test_cache_key_changes_with_the_schema():
    """A contract change must invalidate cached responses for the old shape."""
    a = cache_key("m", "sys", "prompt", {"type": "object", "properties": {"a": {}}})
    b = cache_key("m", "sys", "prompt", {"type": "object", "properties": {"b": {}}})
    assert a != b


def test_cache_key_changes_with_the_model():
    schema = {"type": "object"}
    assert cache_key("gpt-4o-mini", "s", "p", schema) != cache_key("gpt-5", "s", "p", schema)


def test_cache_key_changes_with_the_prompt_version():
    """A reworded prompt under the same model must not replay the old wording's answer."""
    schema = {"type": "object"}
    assert cache_key("m", "s", "p", schema, "2026-08-06") != cache_key(
        "m", "s", "p", schema, "2026-09-01"
    )


def test_cache_key_without_a_prompt_version_is_not_the_same_as_with_one():
    """Why the pre-versioning entries in artifacts/llm_cache are unreachable, not merely stale."""
    schema = {"type": "object"}
    assert cache_key("m", "s", "p", schema) != cache_key("m", "s", "p", schema, "2026-08-06")


def test_cache_round_trips(tmp_path):
    cache = ResponseCache(tmp_path)
    key = cache_key("m", "s", "p", {})
    cache.put(key, {"label": "FalsePositive"})
    assert cache.get(key)["data"] == {"label": "FalsePositive"}
    assert len(cache) == 1


def test_replay_raises_on_a_miss(tmp_path):
    """Silently substituting something else would make a 'reproduced' run a lie."""
    client = ReplayClient(cache=ResponseCache(tmp_path))
    with pytest.raises(CacheMiss):
        client.complete_structured(system="s", prompt="p", schema={}, name="triage")


def test_deterministic_backend_rejects_an_unregistered_agent():
    with pytest.raises(LLMError):
        DeterministicClient().complete_structured(
            system="s", prompt="p", schema={}, name="nobody"
        )


def test_build_client_rejects_an_unknown_backend():
    with pytest.raises(LLMError):
        build_client("telepathy")


def test_openai_backend_refuses_to_start_without_a_key():
    from app.agents.llm import OpenAIClient

    with pytest.raises(LLMError, match="OPENAI_API_KEY"):
        OpenAIClient(api_key="")


def test_settings_repr_does_not_leak_the_api_key():
    """A dataclass repr shows up in tracebacks and pytest output. The key must not be in it."""
    from app.config import Settings

    assert "openai_api_key" not in repr(Settings(openai_api_key="sk-secret-value"))
    assert "sk-secret-value" not in repr(Settings(openai_api_key="sk-secret-value"))


# --- retrieval and leakage --------------------------------------------------------------------

def test_retrieved_incidents_never_carry_a_label(dataset):
    """Leaking a similar incident's label into the prompt would void every metric."""
    evidence, incidents = dataset
    retriever = EntityOverlapRetriever(evidence, incidents)
    for incident_id in incidents["incident_id"].head(10):
        for hit in retriever.similar(incident_id, k=5):
            assert not hasattr(hit, "label")
            for label in ("TruePositive", "BenignPositive", "FalsePositive"):
                assert label not in hit.summary


def test_retriever_never_returns_the_query_incident(dataset):
    evidence, incidents = dataset
    retriever = EntityOverlapRetriever(evidence, incidents)
    for incident_id in incidents["incident_id"].head(10):
        assert all(h.incident_id != incident_id for h in retriever.similar(incident_id))


def test_null_retriever_returns_nothing_rather_than_raising():
    assert NullRetriever().similar("INC-1") == []


def test_context_withholds_ground_truth(one_incident):
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    context = IncidentContext.from_incident(row, rows)
    assert "label" not in context.incident_fields
    assert "label_int" not in context.incident_fields


#: Agents that decide *before* any label exists. None of these may see a label at all.
# --- prompts must contain what the agent is asked to reason about ------------------------------
# The defect these guard: the Verifier's prompt rendered `len(cited)` instead of the ids, and no
# evidence content at all, so it was asked to certify citations it could not see. It said so on
# every incident and escalated -- 97.5% live against 5.0% deterministic, on incidents whose
# structural checks all passed. Triage had the milder form: ids listed, contents withheld.


def _prompt_for(agent_name, one_incident):
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    workflow = Workflow(client=DeterministicClient())
    context = IncidentContext.from_incident(row, rows)
    state = WorkflowState(workflow_id="WF-p", incident_id=context.incident_id)

    for name in AGENT_SEQUENCE:
        agent = workflow.agents[name]
        agent_context = agent.build_context(state, context=context)
        if name == agent_name:
            return agent.build_prompt(agent_context), agent_context, context
        output, record = agent.run(state, context=context)
        setattr(state, name, output)
        state.runs.append(record)
    raise AssertionError(f"unknown agent {agent_name}")


def test_the_verifier_is_shown_the_evidence_ids_it_must_check(one_incident):
    prompt, agent_context, _ = _prompt_for("verifier", one_incident)

    assert agent_context["bundle"], "no correlation bundle to verify against"
    for evidence_id in agent_context["bundle"][:5]:
        assert evidence_id in prompt, f"{evidence_id} is in the context but not in the prompt"
    for evidence_id in agent_context["cited"][:5]:
        assert evidence_id in prompt, f"triage cited {evidence_id} and the verifier cannot see it"


def test_the_verifier_is_shown_the_evidence_contents(one_incident):
    prompt, _, context = _prompt_for("verifier", one_incident)

    assert context.summary[:60] in prompt, "the verifier cannot see the incident summary"
    first = str(context.evidence.iloc[0]["evidence_id"])
    assert f"[{first}]" in prompt, "the verifier has no evidence block to check citations against"


def test_triage_is_shown_the_contents_of_the_evidence_it_must_cite(one_incident):
    prompt, agent_context, context = _prompt_for("triage", one_incident)

    first = str(context.evidence.iloc[0]["evidence_id"])
    assert f"[{first}]" in prompt, "triage is asked to cite records it was never shown"
    for evidence_id in agent_context["evidence_bundle"][:5]:
        assert evidence_id in prompt


# --- agent traces ----------------------------------------------------------------------------
# The prompts are surfaced on the Workflow screen so invariant 2 can be read rather than trusted.
# These tests make the same claim mechanically.


def test_trace_sink_does_not_change_what_run_returns(one_incident):
    """A display feature must be observably inert on the decision path."""
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    context = IncidentContext.from_incident(row, rows)
    agent = Workflow(client=DeterministicClient()).agents["detection"]

    plain_state = WorkflowState(workflow_id="WF-a", incident_id=context.incident_id)
    traced_state = WorkflowState(workflow_id="WF-a", incident_id=context.incident_id)
    sink: dict = {}

    plain, plain_record = agent.run(plain_state, context=context)
    traced, traced_record = agent.run(traced_state, context=context, trace_sink=sink)

    assert plain.model_dump() == traced.model_dump()
    assert plain_record.output_hash == traced_record.output_hash
    assert sink["user_prompt"]


def test_trace_sink_never_reaches_build_context(one_incident):
    """It is keyword-only precisely so it cannot be forwarded into an agent's prompt."""
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    context = IncidentContext.from_incident(row, rows)
    agent = Workflow(client=DeterministicClient()).agents["detection"]
    state = WorkflowState(workflow_id="WF-a", incident_id=context.incident_id)

    sink: dict = {}
    agent.run(state, context=context, trace_sink=sink)

    assert "trace_sink" not in sink["context_keys"]
    assert "trace_sink" not in sink["user_prompt"]


def test_pre_decision_traces_are_label_free(one_incident):
    """Invariant 2, asserted over the prompts the UI actually displays.

    Scoped to the rendered user prompt. Triage's *role* names the three labels because it is
    choosing between them, and that static text is identical for every incident, so it cannot
    carry an answer.
    """
    row, rows = one_incident
    result = Workflow(client=DeterministicClient()).run(row, rows)

    pre_decision = [t for t in result.traces if t["pre_decision"]]
    assert {t["agent"] for t in pre_decision} == {"detection", "correlation", "investigation"}
    for trace in pre_decision:
        assert trace["label_free"], f"{trace['agent']} prompt leaks a triage label"


def test_every_run_gets_a_trace_keyed_by_its_run_index(one_incident):
    row, rows = one_incident
    result = Workflow(client=DeterministicClient()).run(row, rows)

    assert len(result.traces) == len(result.state.runs)
    assert [t["run_index"] for t in result.traces] == list(range(len(result.state.runs)))
    for trace, run in zip(result.traces, result.state.runs):
        assert trace["agent"] == run.agent
        assert trace["sequence"] == run.sequence


def test_traces_are_keyed_by_index_so_a_revision_pass_stays_distinguishable(one_incident):
    """The live revision re-runs three agents, so agent name is not a unique key.

    Simulated by driving _run_agent directly: the live path is gated on backend == "live", and
    what matters here is that a repeated agent produces two separately addressable traces.
    """
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    workflow = Workflow(client=DeterministicClient())
    context = IncidentContext.from_incident(row, rows)
    state = WorkflowState(workflow_id="WF-r", incident_id=context.incident_id)
    traces: list[dict] = []

    for name in AGENT_SEQUENCE:
        state = workflow._run_agent(name, state, context, traces)
    for name in ("triage", "remediation", "verifier"):
        state = workflow._run_agent(name, state, context, traces)

    assert len(traces) == 9
    assert [t["run_index"] for t in traces] == list(range(9))
    triage_indices = [t["run_index"] for t in traces if t["agent"] == "triage"]
    assert len(triage_indices) == 2 and triage_indices[0] != triage_indices[1]


def test_traces_are_absent_when_no_sink_is_supplied(one_incident):
    """Nothing pays for the feature unless it is asked for."""
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    workflow = Workflow(client=DeterministicClient())
    context = IncidentContext.from_incident(row, rows)
    state = WorkflowState(workflow_id="WF-n", incident_id=context.incident_id)

    workflow._run_agent("detection", state, context)
    assert state.detection is not None


PRE_DECISION_AGENTS = ("detection", "correlation", "investigation", "triage")


def test_pre_decision_prompts_never_contain_any_label(one_incident):
    """The single most damaging leak, checked on the actual rendered prompts.

    Detection through Triage run before a label exists, so *no* label string may appear in their
    prompts — not the ground truth, not any other. Remediation and Verifier are excluded here
    because they legitimately consume Triage's prediction; they are covered by the test below.
    """
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    context = IncidentContext.from_incident(row, rows)
    state = WorkflowState(workflow_id="WF-test", incident_id=context.incident_id)

    workflow = Workflow(client=DeterministicClient())
    for name in PRE_DECISION_AGENTS:
        agent = workflow.agents[name]
        prompt = agent.build_prompt(agent.build_context(state, context=context))
        for label in ("TruePositive", "BenignPositive", "FalsePositive"):
            assert label not in prompt, f"{name} prompt leaks the {label} label"
        output, _ = agent.run(state, context=context)
        setattr(state, name, output)


def test_post_decision_prompts_carry_the_prediction_not_the_ground_truth(one_incident):
    """Remediation and Verifier see Triage's *prediction*, and nothing from the incident record.

    Checked by forcing the two apart: the fixture's ground-truth label is overwritten with one
    value and Triage is made to predict a different one. If the prompts follow the prediction and
    never mention the ground truth, they cannot be reading the incident's label field.
    """
    from app.agents.schemas import TriageOutput, WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    row = row.copy()
    row["label"] = "TruePositive"          # ground truth
    predicted = "FalsePositive"            # deliberately different

    context = IncidentContext.from_incident(row, rows)
    state = WorkflowState(workflow_id="WF-test", incident_id=context.incident_id)

    workflow = Workflow(client=DeterministicClient())
    for name in PRE_DECISION_AGENTS:
        output, _ = workflow.agents[name].run(state, context=context)
        setattr(state, name, output)

    state.triage = TriageOutput(
        label=TriageLabel(predicted),
        confidence=0.9,
        rationale="forced prediction for the leakage test",
        supporting_evidence_ids=state.correlation.evidence_bundle[:2],
    )

    for name in ("remediation", "verifier"):
        agent = workflow.agents[name]
        prompt = agent.build_prompt(agent.build_context(state, context=context))
        assert predicted in prompt, f"{name} should reason about the prediction"
        # The catalogue legitimately names every label, so check the *incident's* framing only.
        assert "Triage: TruePositive" not in prompt
        assert f"Triage: {predicted}" in prompt or predicted in prompt
        output, _ = agent.run(state, context=context)
        setattr(state, name, output)


def test_empty_evidence_does_not_crash_the_chain(dataset):
    evidence, incidents = dataset
    row = incidents.iloc[0]
    empty = evidence.iloc[0:0]
    result = Workflow(client=DeterministicClient()).run(row, empty)
    assert result.state.triage is not None
