"""The agent chain: happy path, failure handling, and the guarantees that must not slip.

The failure tests carry most of the weight. Any chain works when everything works; what matters is
that a timeout produces a marked degradation rather than a confident-looking wrong answer.
"""

from __future__ import annotations

import pandas as pd
import pytest

from app.agents.llm import (
    CacheMiss,
    CacheOnlyClient,
    DeterministicClient,
    FailingClient,
    LLMError,
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
    assert [r.sequence for r in state.runs] == [1, 2, 3, 4]


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


def test_cache_round_trips(tmp_path):
    cache = ResponseCache(tmp_path)
    key = cache_key("m", "s", "p", {})
    cache.put(key, {"label": "FalsePositive"})
    assert cache.get(key)["data"] == {"label": "FalsePositive"}
    assert len(cache) == 1


def test_cache_only_backend_raises_on_a_miss(tmp_path):
    """Silently substituting something else would make a 'reproduced' run a lie."""
    client = CacheOnlyClient(cache=ResponseCache(tmp_path))
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


def test_agent_prompts_never_contain_the_ground_truth_label(one_incident):
    """The single most damaging leak, checked on the actual rendered prompts."""
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    row, rows = one_incident
    truth = row["label"]
    context = IncidentContext.from_incident(row, rows)
    state = WorkflowState(workflow_id="WF-test", incident_id=context.incident_id)

    workflow = Workflow(client=DeterministicClient())
    for name in AGENT_SEQUENCE:
        agent = workflow.agents[name]
        prompt = agent.build_prompt(agent.build_context(state, context=context))
        assert truth not in prompt, f"{name} prompt leaks the ground-truth label"
        output, _ = agent.run(state, context=context)
        setattr(state, name, output)


def test_empty_evidence_does_not_crash_the_chain(dataset):
    evidence, incidents = dataset
    row = incidents.iloc[0]
    empty = evidence.iloc[0:0]
    result = Workflow(client=DeterministicClient()).run(row, empty)
    assert result.state.triage is not None
