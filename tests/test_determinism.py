"""What "the same result every time" actually means here, asserted rather than claimed.

The honest position, which these tests encode:

* **Replay is reproducible and hermetic.** A prewarmed incident replays byte-identically and makes
  zero outbound calls, even on a machine with a live API key in ``.env``.
* **Deterministic mode is reproducible.** Same input, same ``output_hash``, no network.
* **Live is not reproducible.** The active models are reasoning models with no ``temperature``,
  ``top_p`` or seed to pin, and a retry re-sends an identical prompt. That is measured by
  ``scripts/measure_variance.py``, not asserted here.

The remaining tests guard the paths by which a hallucination or a stale response could reach a
decision: invented similar-case ids, invented MITRE techniques, and untrustworthy cache entries.
"""

from __future__ import annotations

import json
import time

import pytest

from app.agents.investigation import InvestigationAgent
from app.agents.llm import (
    CACHE_SCHEMA_VERSION,
    CacheMiss,
    DeterministicClient,
    LLMError,
    ReplayClient,
    ResponseCache,
    build_client,
    cache_key,
    model_for_agent,
)
from app.agents.schemas import DetectionOutput, InvestigationOutput, MitreMapping, SimilarCase
from app.config import LLM_CACHE_DIR, settings
from app.data import incidents as incidents_mod, loader
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow

DETECTION_ARGS = dict(
    system="s",
    prompt="p",
    schema=DetectionOutput.model_json_schema(),
    name="detection",
    output_type=DetectionOutput,
)


# --- hermetic replay ---------------------------------------------------------------------------

def test_replay_is_hermetic_even_with_a_key_present(monkeypatch, tmp_path):
    """Replay must never call out, on a machine whose .env holds a real key.

    This is the guard on the demo's worst failure mode: a cache miss quietly becoming a paid
    8-25 second live call that returns a label nobody rehearsed. Deliberately asserted against the
    *actual* configured key rather than a patched one -- `Settings` is a frozen dataclass so the
    key cannot leak through a repr, and patching it would test a machine nobody runs the demo on.
    """
    import agents

    if not settings.openai_api_key:
        pytest.skip("no OPENAI_API_KEY configured; nothing to be hermetic against")

    def explode(*args, **kwargs):
        pytest.fail("replay made an outbound call")

    monkeypatch.setattr(agents.Runner, "run_sync", staticmethod(explode))

    client = ReplayClient(cache=ResponseCache(tmp_path))
    assert client.allow_live_fill is False
    assert client.live is None

    with pytest.raises(CacheMiss):
        client.complete_structured(**DETECTION_ARGS)


def test_hermetic_replay_ignores_an_injected_live_client(tmp_path):
    """Hermetic has to mean hermetic, not "hermetic unless a caller passes something in"."""
    from app.agents.llm import FailingClient

    client = ReplayClient(cache=ResponseCache(tmp_path), live=FailingClient(failures=99))
    assert client.live is None
    with pytest.raises(CacheMiss):
        client.complete_structured(**DETECTION_ARGS)


def test_build_client_returns_a_hermetic_replay_backend():
    client = build_client("replay")
    assert client.allow_live_fill is False and client.live is None


def test_live_fill_is_opt_in_and_needs_a_key(tmp_path):
    with pytest.raises(LLMError):
        ReplayClient(cache=ResponseCache(tmp_path), api_key="", allow_live_fill=True)


# --- cache trust -------------------------------------------------------------------------------

def _store(cache: ResponseCache, meta: dict) -> str:
    key = cache_key(
        model_for_agent("detection"),
        DETECTION_ARGS["system"],
        DETECTION_ARGS["prompt"],
        DETECTION_ARGS["schema"],
        settings.agent_prompt_version,
    )
    cache.path_for(key).write_text(
        json.dumps({"data": {"severity_score": 0.5, "suspicious_entities": [],
                             "initial_reason": "x" * 40}, "meta": meta}),
        encoding="utf-8",
    )
    return key


def test_replay_rejects_a_cache_entry_without_a_prompt_version(tmp_path):
    """Why the 274 pre-versioning entries were unreachable, not merely stale."""
    cache = ResponseCache(tmp_path)
    _store(cache, {"model": model_for_agent("detection")})
    with pytest.raises(CacheMiss):
        ReplayClient(cache=cache).complete_structured(**DETECTION_ARGS)


def test_replay_rejects_a_cache_entry_from_another_model(tmp_path):
    cache = ResponseCache(tmp_path)
    _store(cache, {"model": "gpt-4o-mini", "prompt_version": settings.agent_prompt_version})
    with pytest.raises(CacheMiss):
        ReplayClient(cache=cache).complete_structured(**DETECTION_ARGS)


def test_a_suspect_entry_is_rejected_from_the_production_store():
    """Zero latency with real token counts is a fake runner's fingerprint, not a fast response."""
    entry = {"meta": {"model": "m", "prompt_version": "v", "latency_ms": 0,
                      "prompt_tokens": 120, "completion_tokens": 24}}
    trusted, reason = ResponseCache.is_trustworthy(entry, "m", "v", strict_latency=True)
    assert trusted is False and "zero latency" in reason

    # Tolerated off-production: a test writing through the real client produces this legitimately.
    assert ResponseCache.is_trustworthy(entry, "m", "v", strict_latency=False)[0] is True


def test_the_production_cache_is_not_writable_from_tests():
    """A test once wrote fabricated responses into the store the demo replays from."""
    cache = ResponseCache(LLM_CACHE_DIR)
    assert cache.is_production is True
    with pytest.raises(LLMError):
        cache.put("0" * 64, {"anything": True})


def test_writes_are_provenance_stamped(tmp_path):
    cache = ResponseCache(tmp_path)
    cache.put("a" * 64, {"x": 1})
    meta = cache.get("a" * 64)["meta"]
    assert meta["cache_schema"] == CACHE_SCHEMA_VERSION
    assert meta["written_at"] and meta["written_by"]


# --- grounding: the two fields most likely to be confabulated ----------------------------------

def _investigation_context(similar=(), techniques=()):
    return {
        "incident_id": "INC-test",
        "evidence_bundle": ["EVD-1", "EVD-2"],
        "similar": [{"incident_id": value} for value in similar],
        "techniques": list(techniques),
    }


def _investigation_output(similar_ids=(), technique_ids=()):
    return InvestigationOutput(
        similar_cases=[
            SimilarCase(incident_id=value, similarity=0.5, why_similar="shares an account")
            for value in similar_ids
        ],
        mitre_mapping=[
            MitreMapping(
                technique_id=value,
                technique_name="whatever",
                supporting_evidence_ids=["EVD-1"],
            )
            for value in technique_ids
        ],
        investigation_summary="A summary long enough to satisfy the contract's minimum length.",
    )


def test_grounding_rejects_an_invented_similar_case_id():
    """There is no legitimate route by which the model could know another incident's id."""
    agent = InvestigationAgent(DeterministicClient())
    context = _investigation_context(similar=["INC-real"])

    agent.validate_grounding(_investigation_output(similar_ids=["INC-real"]), context)

    with pytest.raises(ValueError, match="invented similar-case"):
        agent.validate_grounding(_investigation_output(similar_ids=["INC-notreal"]), context)


def test_grounding_rejects_an_invented_mitre_technique():
    agent = InvestigationAgent(DeterministicClient())
    context = _investigation_context(techniques=["T1078"])

    with pytest.raises(ValueError, match="MITRE technique"):
        agent.validate_grounding(_investigation_output(technique_ids=["T9999"]), context)


def test_grounding_accepts_a_known_technique_the_detector_did_not_tag():
    """A union allowlist on purpose: a model may map beyond the detector, but not beyond reality."""
    agent = InvestigationAgent(DeterministicClient())
    agent.validate_grounding(
        _investigation_output(technique_ids=["T1566"]), _investigation_context(techniques=[])
    )


def test_grounding_accepts_a_sub_technique_of_a_known_parent():
    agent = InvestigationAgent(DeterministicClient())
    agent.validate_grounding(
        _investigation_output(technique_ids=["T1566.001"]), _investigation_context(techniques=[])
    )


def test_the_investigation_fallback_never_trips_its_own_grounding_checks(evidence, incident_table):
    """A fallback that fails validation would degrade twice and mask the real cause."""
    from app.orchestration.context import IncidentContext
    from app.agents.schemas import WorkflowState

    row = incident_table.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    context_obj = IncidentContext.from_incident(row, rows)
    agent = InvestigationAgent(DeterministicClient())

    state = WorkflowState(
        workflow_id="WF-test",
        incident_id=str(row["incident_id"]),
        evidence_ids=context_obj.evidence_ids,
    )
    context = agent.build_context(state, context=context_obj)
    agent.validate_grounding(agent.fallback(context), context)


# --- reproducibility ---------------------------------------------------------------------------

def test_deterministic_mode_reproduces_an_identical_output_hash(evidence, incident_table):
    row = incident_table.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])

    first = Workflow(client=DeterministicClient()).run(row, rows)
    second = Workflow(client=DeterministicClient()).run(row, rows)

    assert first.state.output_hash == second.state.output_hash
    assert first.state.evidence_hash == second.state.evidence_hash
    assert first.revision_fired is False and second.revision_fired is False


def test_a_hung_live_call_degrades_within_its_budget(
    monkeypatch, tmp_path, evidence, incident_table
):
    """A hung stage must cost one budget, not the demo. Invariant 9 does the rest.

    `llm_timeout_seconds` was read into the client and then never passed to anything, so before
    this guard a stalled request could hang the run indefinitely.
    """
    import agents

    from app.agents.detection import DetectionAgent
    from app.agents.llm import AgentsSDKClient
    from app.agents.schemas import WorkflowState
    from app.orchestration.context import IncidentContext

    monkeypatch.setattr(
        agents.Runner, "run_sync", staticmethod(lambda *a, **k: time.sleep(30))
    )
    client = AgentsSDKClient(api_key="sk-test", cache=ResponseCache(tmp_path))
    client.wall_clock = 1

    row = incident_table.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    context = IncidentContext.from_incident(row, rows)

    agent = DetectionAgent(client, sequence=1)
    state = WorkflowState(
        workflow_id="WF-x",
        incident_id=str(row["incident_id"]),
        evidence_ids=context.evidence_ids,
    )

    started = time.perf_counter()
    _, record = agent.run(state, context=context)
    elapsed = time.perf_counter() - started

    assert record.status == "fallback"
    assert "wall-clock" in record.validation_error
    # Two attempts at a one-second budget each; anything near 30s means the guard did not fire.
    assert elapsed < 10


# --- the variance harness must not pollute the replay cache -------------------------------------

def test_the_variance_cache_never_reads_or_writes():
    """Both halves matter: a read would make run 2 a replay of run 1 and measure nothing;
    a write would put unvalidated samples into the store the demo replays from."""
    from scripts.measure_variance import NoWriteCache

    cache = NoWriteCache()
    assert cache.is_production is False

    cache.put("b" * 64, {"anything": True})
    assert cache.get("b" * 64) is None
    assert list(cache.directory.glob("*.json")) == []


def test_a_variance_sweep_leaves_the_production_cache_untouched():
    from scripts.measure_variance import NoWriteCache

    before = len(ResponseCache(LLM_CACHE_DIR))
    cache = NoWriteCache()
    for index in range(5):
        cache.put(f"{index:064d}", {"sample": index})
    assert len(ResponseCache(LLM_CACHE_DIR)) == before


# --- the demo gate -----------------------------------------------------------------------------

def _manifest() -> dict:
    path = LLM_CACHE_DIR / "demo_manifest.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


_MANIFEST = _manifest()
_ARC_READY = bool(_MANIFEST.get("ready")) and bool(_MANIFEST.get("replay_verified"))

arc_gate = pytest.mark.skipif(
    not _ARC_READY, reason="demo arc not prewarmed; run scripts/prewarm_replay.py"
)


@arc_gate
@pytest.mark.parametrize("rank", [1, 2, 3, 4, 5, 6])
def test_every_demo_arc_case_replays_at_a_full_cache_hit_under_a_second(rank):
    """The gate the demo actually rests on: six cases, zero network, sub-second, same hash."""
    from app.retrieval import hybrid
    from app.retrieval.base import EntityOverlapRetriever
    from app.services import scoring
    from app.config import ARTIFACTS

    entry = _MANIFEST["arc"][str(rank)]
    evidence_frame, incidents = loader.load_prepared()
    model = scoring.load_baseline()
    retriever = hybrid.load_if_available(ARTIFACTS / "index") or EntityOverlapRetriever(
        evidence_frame, incidents
    )

    row = incidents[incidents["incident_id"] == entry["incident_id"]].iloc[0]
    rows = incidents_mod.evidence_for(evidence_frame, entry["incident_id"])

    started = time.perf_counter()
    result = Workflow(client=ReplayClient(), retriever=retriever).run(
        row, rows, baseline_model=model
    )
    elapsed = time.perf_counter() - started

    assert [run.status for run in result.state.runs] == ["ok"] * len(AGENT_SEQUENCE)
    assert all(run.cached for run in result.state.runs), "a stage was not served from the cache"
    assert result.degraded_agents() == []
    assert result.state.output_hash == entry["replay_output_hash"]
    assert elapsed < 1.0, f"case {rank} replayed in {elapsed:.2f}s"
