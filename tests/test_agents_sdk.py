from __future__ import annotations

import pytest

from app.agents.llm import (
    AgentsSDKClient,
    CacheMiss,
    ReplayClient,
    ResponseCache,
    model_for_agent,
    normalize_mode,
)
from app.agents.schemas import DetectionOutput


class FakeUsage:
    input_tokens = 120
    output_tokens = 24


class FakeContextWrapper:
    usage = FakeUsage()


class FakeResult:
    context_wrapper = FakeContextWrapper()

    def __init__(self, output):
        self.output = output

    def final_output_as(self, cls, raise_if_incorrect_type=False):
        assert isinstance(self.output, cls)
        return self.output


def detection_output():
    return DetectionOutput(
        severity_score=0.72,
        suspicious_entities=[],
        initial_reason="Detector and entity evidence warrant investigation.",
    )


def test_execution_mode_aliases_are_compatible():
    assert normalize_mode("cache") == "replay"
    assert normalize_mode("openai") == "live"
    assert normalize_mode("deterministic") == "deterministic"


def test_model_routing_separates_support_and_judge_roles():
    assert model_for_agent("detection").endswith("terra")
    assert model_for_agent("triage").endswith("sol")
    assert model_for_agent("verifier").endswith("sol")


def test_agents_sdk_uses_typed_output_bounded_tools_and_redacted_trace(monkeypatch, tmp_path):
    import agents

    captured = {}

    def fake_set_tracing_disabled(disabled):
        captured["tracing_globally_disabled"] = disabled

    def fake_run(starting_agent, prompt, **kwargs):
        captured["agent"] = starting_agent
        captured["prompt"] = prompt
        captured["config"] = kwargs["run_config"]
        return FakeResult(detection_output())

    monkeypatch.setattr(agents.Runner, "run_sync", staticmethod(fake_run))
    monkeypatch.setattr(agents, "set_tracing_disabled", fake_set_tracing_disabled)
    client = AgentsSDKClient(api_key="sk-test", cache=ResponseCache(tmp_path))
    response = client.complete_structured(
        system="bounded system instruction",
        prompt="inspect this incident",
        schema=DetectionOutput.model_json_schema(),
        name="detection",
        output_type=DetectionOutput,
        tool_context={
            "evidence_ids": [f"EVD-{index}" for index in range(80)],
            "similar": [{"incident_id": f"INC-{index}"} for index in range(20)],
            "clusters": [{"cluster_id": "CLU-1"}],
        },
    )

    assert response.data["severity_score"] == 0.72
    assert response.model.endswith("terra")
    assert response.prompt_tokens == 120
    assert {tool.name for tool in captured["agent"].tools} == {
        "lookup_evidence",
        "search_similar",
        "get_graph_context",
    }
    assert captured["config"].trace_include_sensitive_data is False
    assert captured["config"].tracing_disabled is True
    assert captured["tracing_globally_disabled"] is True
    assert response.trace_id == ""
    assert "inspect this incident" not in captured["config"].trace_metadata.values()


def test_replay_reads_validated_sdk_output_without_running_live(monkeypatch, tmp_path):
    import agents

    calls = 0

    def fake_run(*args, **kwargs):
        nonlocal calls
        calls += 1
        return FakeResult(detection_output())

    monkeypatch.setattr(agents.Runner, "run_sync", staticmethod(fake_run))
    cache = ResponseCache(tmp_path)
    live = AgentsSDKClient(api_key="sk-test", cache=cache)
    arguments = dict(
        system="s",
        prompt="p",
        schema=DetectionOutput.model_json_schema(),
        name="detection",
        output_type=DetectionOutput,
        tool_context={"evidence_ids": ["EVD-1"]},
    )
    live.complete_structured(**arguments)
    replay = ReplayClient(cache=cache, api_key="")
    response = replay.complete_structured(**arguments)
    assert calls == 1
    assert response.cached is True
    assert response.backend == "replay"


def test_replay_miss_never_makes_an_outbound_call_without_a_key(tmp_path):
    replay = ReplayClient(cache=ResponseCache(tmp_path), api_key="")
    with pytest.raises(CacheMiss):
        replay.complete_structured(
            system="s",
            prompt="p",
            schema=DetectionOutput.model_json_schema(),
            name="detection",
            output_type=DetectionOutput,
        )
