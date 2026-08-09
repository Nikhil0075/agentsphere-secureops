from __future__ import annotations

import sys
from types import SimpleNamespace

import pandas as pd
import pytest

from app.agents.llm import LLMError, LLMResponse, ReplayClient, ResponseCache, cache_key
from app.config import settings
from scripts import prewarm_replay


class FakeLiveClient:
    backend = "live"
    model = "fake-live"

    def __init__(self) -> None:
        self.calls = 0

    def complete_structured(self, **kwargs):
        self.calls += 1
        return LLMResponse(data={"ok": True}, backend="live", model=self.model)


def test_live_stage_budget_is_a_hard_ceiling():
    live = FakeLiveClient()
    budget = prewarm_replay.LiveStageBudget(live, maximum=2)

    budget.complete_structured(name="detection")
    budget.complete_structured(name="correlation")

    with pytest.raises(LLMError, match="budget exhausted"):
        budget.complete_structured(name="investigation")
    assert budget.used == 2
    assert live.calls == 2


def test_replay_cache_hits_do_not_consume_paid_budget(tmp_path):
    cache = ResponseCache(tmp_path)
    live = FakeLiveClient()
    budget = prewarm_replay.LiveStageBudget(live, maximum=1)
    client = ReplayClient(cache=cache, live=budget, allow_live_fill=True)
    arguments = {
        "system": "system",
        "prompt": "cached prompt",
        "schema": {"type": "object"},
        "name": "detection",
    }
    model = settings.openai_support_model
    key = cache_key(
        model,
        arguments["system"],
        arguments["prompt"],
        arguments["schema"],
        settings.agent_prompt_version,
    )
    cache.put(
        key,
        {"cached": True},
        {
            "model": model,
            "prompt_version": settings.agent_prompt_version,
            "latency_ms": 10,
        },
    )

    response = client.complete_structured(**arguments)
    assert response.cached
    assert budget.used == 0

    client.complete_structured(**{**arguments, "prompt": "uncached prompt"})
    assert budget.used == 1


def test_paid_prewarm_refuses_to_start_without_an_explicit_budget(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["prewarm_replay.py"])
    monkeypatch.setattr(
        prewarm_replay.loader,
        "load_prepared",
        lambda: (_ for _ in ()).throw(AssertionError("data should not be loaded")),
    )

    assert prewarm_replay.main() == 2
    assert "REFUSED" in capsys.readouterr().err


def test_verify_only_rejects_paid_or_force_options_before_loading_data(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["prewarm_replay.py", "--verify-only", "--max-live-stages", "1"],
    )
    monkeypatch.setattr(
        prewarm_replay.loader,
        "load_prepared",
        lambda: (_ for _ in ()).throw(AssertionError("data should not be loaded")),
    )

    assert prewarm_replay.main() == 2
    assert "cannot be combined" in capsys.readouterr().err


def test_verify_only_never_constructs_a_live_client(monkeypatch, tmp_path):
    incident = {
        "incident_id": "INC-test",
        "demo_rank": 5,
        "demo_role": "low_risk_false_positive",
    }
    incidents = pd.DataFrame([incident])
    evidence = pd.DataFrame([{"incident_id": "INC-test"}])
    runs = [SimpleNamespace(cached=True) for _ in prewarm_replay.AGENT_SEQUENCE]
    result = SimpleNamespace(
        gate=SimpleNamespace(
            auto_approved=True,
            action_risk="low",
            failed_policies=lambda: [],
        ),
        state=SimpleNamespace(
            requires_approval=False,
            verifier=SimpleNamespace(verdict=SimpleNamespace(value="accept")),
            remediation=SimpleNamespace(recommended_action="close_as_false_positive"),
            output_hash="0xtest",
            runs=runs,
        ),
        label="FalsePositive",
        confidence=0.72,
        degraded_agents=lambda: [],
    )

    class FakeWorkflow:
        def __init__(self, **kwargs):
            pass

        def run(self, *args, **kwargs):
            return result

    monkeypatch.setattr(sys, "argv", ["prewarm_replay.py", "--verify-only"])
    monkeypatch.setattr(prewarm_replay, "MANIFEST", tmp_path / "manifest.json")
    monkeypatch.setattr(prewarm_replay, "ensure_dirs", lambda: None)
    monkeypatch.setattr(prewarm_replay.loader, "load_prepared", lambda: (evidence, incidents))
    monkeypatch.setattr(prewarm_replay.scoring, "load_baseline", lambda: object())
    monkeypatch.setattr(
        prewarm_replay.scoring,
        "prepare_queue_table",
        lambda frame, model: frame,
    )
    monkeypatch.setattr(prewarm_replay.hybrid, "load_if_available", lambda path: object())
    monkeypatch.setattr(
        prewarm_replay.incidents_mod,
        "evidence_for",
        lambda frame, incident_id: frame,
    )
    monkeypatch.setattr(prewarm_replay, "Workflow", FakeWorkflow)
    monkeypatch.setattr(
        prewarm_replay,
        "AgentsSDKClient",
        lambda: (_ for _ in ()).throw(AssertionError("live client constructed")),
    )

    assert prewarm_replay.main() == 0
    manifest = prewarm_replay.json.loads(
        (tmp_path / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["ready"] is True
    assert manifest["verification_mode"] == "replay_only"


def test_manifest_snapshot_makes_the_arc_autonomy_contract_machine_checkable():
    result = SimpleNamespace(
        gate=SimpleNamespace(
            auto_approved=True,
            action_risk="low",
            failed_policies=lambda: [],
        ),
        state=SimpleNamespace(
            requires_approval=False,
            verifier=SimpleNamespace(verdict=SimpleNamespace(value="accept")),
            remediation=SimpleNamespace(recommended_action="close_as_false_positive"),
        ),
        label="FalsePositive",
        confidence=0.72,
    )

    expected = prewarm_replay.expected_auto_approval({"demo_rank": 5})
    snapshot = prewarm_replay.outcome_snapshot(result, expected)
    assert expected is True
    assert snapshot["matches_arc_contract"] is True
    assert snapshot["auto_approved"] is True

    mismatch = prewarm_replay.outcome_snapshot(result, expected=False)
    assert mismatch["matches_arc_contract"] is False
