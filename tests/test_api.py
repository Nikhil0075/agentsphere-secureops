"""Every API route, against the real prepared corpus.

Skipped wholesale when the corpus has not been prepared, so a fresh clone does not report
failures for work that simply has not been run yet.
"""

from __future__ import annotations

import pytest

from app.data import loader

pytest.importorskip("fastapi")

if not loader.INCIDENTS_PARQUET.exists():
    pytest.skip("run scripts/prepare_data.py first", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

from app.api.main import app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def offline_chain():
    """Keep the suite off the network.

    Once a real deployment exists, ``/api/dataset`` and the proof routes reach a public Sepolia
    RPC on every call, which took this file from 4s to ~55s and made it fail whenever that
    endpoint was down. Tests assert the *degradation* path — which is the behaviour that has to
    hold at demo time anyway — and the chain-available path is covered by
    tests/test_blockchain_client.py and the Hardhat suite against a real EVM.
    """
    from app.api.state import AppState
    from app.blockchain.client import ChainClient

    unavailable = ChainClient(unavailable_reason="chain disabled for tests")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(AppState, "chain", lambda self: unavailable)
        yield


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def incident_id(client):
    return client.get("/api/incidents", params={"limit": 1}).json()[0]["incident_id"]


# --- dataset and health --------------------------------------------------------------------

def test_health_reports_ready(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_dataset_describes_the_corpus(client):
    body = client.get("/api/dataset").json()
    assert body["incidents"] > 0
    assert body["evidence_rows"] > 0
    assert set(body["labels"]) <= {"TruePositive", "BenignPositive", "FalsePositive"}


def test_dataset_reports_chain_status_without_requiring_one(client):
    chain = client.get("/api/dataset").json()["chain"]
    assert chain["available"] is False
    assert chain["reason"]


# --- queue ---------------------------------------------------------------------------------

def test_queue_returns_incidents(client):
    body = client.get("/api/incidents", params={"limit": 10}).json()
    assert 0 < len(body) <= 10


def test_queue_is_ordered_by_risk(client):
    """The analyst must see the queue the system actually works through."""
    scores = [r["risk_score"] for r in client.get("/api/incidents", params={"limit": 25}).json()]
    assert scores == sorted(scores, reverse=True)


def test_queue_paging_does_not_repeat_incidents(client):
    first = client.get("/api/incidents", params={"limit": 5, "offset": 0}).json()
    second = client.get("/api/incidents", params={"limit": 5, "offset": 5}).json()
    assert {r["incident_id"] for r in first}.isdisjoint({r["incident_id"] for r in second})


def test_queue_filters_by_label(client):
    body = client.get(
        "/api/incidents", params={"limit": 10, "label": "TruePositive"}
    ).json()
    assert all(r["label"] == "TruePositive" for r in body)


def test_queue_search_matches_an_incident_id(client, incident_id):
    body = client.get("/api/incidents", params={"search": incident_id, "limit": 5}).json()
    assert any(r["incident_id"] == incident_id for r in body)


def test_queue_rejects_an_absurd_limit(client):
    assert client.get("/api/incidents", params={"limit": 100000}).status_code == 422


# --- incident detail -------------------------------------------------------------------------

def test_incident_detail_includes_a_summary(client, incident_id):
    body = client.get(f"/api/incidents/{incident_id}").json()
    assert body["incident_id"] == incident_id
    assert isinstance(body["entity_counts"], dict)


def test_unknown_incident_is_a_404(client):
    assert client.get("/api/incidents/INC-nope").status_code == 404


def test_evidence_rows_are_returned(client, incident_id):
    body = client.get(f"/api/incidents/{incident_id}/evidence", params={"limit": 10}).json()
    assert body
    assert body[0]["evidence_id"].startswith("EVD-")


def test_similar_incidents_never_include_the_query(client, incident_id):
    body = client.get(f"/api/incidents/{incident_id}/similar", params={"k": 5}).json()
    assert all(r["incident_id"] != incident_id for r in body)


def test_similar_incidents_carry_no_label(client, incident_id):
    """The leakage boundary holds at the API edge too."""
    body = client.get(f"/api/incidents/{incident_id}/similar", params={"k": 5}).json()
    for hit in body:
        assert "label" not in hit
        for label in ("TruePositive", "BenignPositive", "FalsePositive"):
            assert label not in hit["summary"]


def test_graph_returns_a_bounded_blast_radius(client, incident_id):
    body = client.get(f"/api/incidents/{incident_id}/graph", params={"max_hops": 2}).json()
    assert body["blast_radius"]["total_nodes"] >= 0
    assert isinstance(body["blast_radius"]["impacted_by_type"], dict)


def test_graph_respects_the_hub_threshold(client, incident_id):
    """A low threshold makes almost everything a hub; the call must still return promptly."""
    body = client.get(
        f"/api/incidents/{incident_id}/graph", params={"max_hops": 3, "hub_degree": 10}
    ).json()
    assert "blast_radius" in body


def test_graph_rejects_a_hub_threshold_below_the_floor(client, incident_id):
    """Guarding the guard: a threshold of 1 would block every expansion and return nothing,
    which looks like 'no impact' rather than 'you asked the wrong question'."""
    response = client.get(
        f"/api/incidents/{incident_id}/graph", params={"hub_degree": 1}
    )
    assert response.status_code == 422


# --- workflow --------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def workflow(client, incident_id):
    response = client.post(
        "/api/workflows",
        json={"incident_id": incident_id, "backend": "deterministic", "persist": True},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_workflow_runs_all_six_agents(workflow):
    assert len(workflow["runs"]) == 6
    for agent in (
        "detection",
        "correlation",
        "investigation",
        "triage",
        "remediation",
        "verifier",
    ):
        assert workflow[agent] is not None


def test_workflow_returns_a_gate_decision(workflow):
    assert workflow["gate"] is not None
    assert workflow["gate"]["requires_approval"] == workflow["requires_approval"]
    assert workflow["gate"]["checks"]


def test_workflow_returns_hashes(workflow):
    assert workflow["evidence_hash"].startswith("0x")
    assert workflow["output_hash"].startswith("0x")


def test_workflow_persists_a_decision(workflow):
    assert workflow["decision_id"].startswith("DEC-")


def test_workflow_on_an_unknown_incident_is_a_404(client):
    response = client.post("/api/workflows", json={"incident_id": "INC-nope"})
    assert response.status_code == 404


def test_workflow_response_matches_the_frozen_contracts(workflow):
    """The API reuses the agent schemas, so it cannot drift from them."""
    from app.agents.schemas import TriageOutput, VerifierOutput

    TriageOutput.model_validate(workflow["triage"])
    VerifierOutput.model_validate(workflow["verifier"])


# --- approval and proof ------------------------------------------------------------------------

def test_verify_recomputes_the_hashes_from_stored_data(client, workflow):
    """The recomputed digest must equal what the workflow produced.

    Stronger than checking a stored column echoes back: this asserts the stored agent outputs and
    evidence rows still hash to the digest the run committed to.
    """
    body = client.get(f"/api/decisions/{workflow['decision_id']}/verify").json()
    assert body["found"]
    assert body["recomputed_evidence_hash"] == workflow["evidence_hash"]
    assert body["recomputed_output_hash"] == workflow["output_hash"]


def test_tamper_then_verify_shows_the_record_as_altered(client, workflow):
    """The Day 6 demo, over HTTP."""
    decision_id = workflow["decision_id"]
    client.post(f"/api/decisions/{decision_id}/restore")

    # Anchor first: with nothing anchored there is no digest to compare against, and verify
    # correctly reports `valid: null` rather than inventing a verdict. The chain is stubbed
    # unavailable here, so this records the proof row locally — which is the degraded path.
    client.post(f"/api/decisions/{decision_id}/anchor")

    before = client.get(f"/api/decisions/{decision_id}/verify").json()
    assert before["valid"] is True

    tampered = client.post(
        f"/api/decisions/{decision_id}/tamper", json={"agent": "triage"}
    ).json()
    assert tampered["before"] != tampered["after"]
    assert tampered["integrity"]["valid"] is False
    assert "agent output" in tampered["integrity"]["tampered"]

    after = client.get(f"/api/decisions/{decision_id}/verify").json()
    assert after["valid"] is False
    assert after["recomputed_output_hash"] != after["anchored_output_hash"]

    restored = client.post(f"/api/decisions/{decision_id}/restore").json()
    assert restored["integrity"]["valid"] is not False


def test_tamper_on_an_unknown_decision_is_a_404(client):
    assert (
        client.post("/api/decisions/DEC-nope/tamper", json={"agent": "triage"}).status_code
        == 404
    )


def test_tamper_with_an_unknown_agent_is_a_400(client, workflow):
    response = client.post(
        f"/api/decisions/{workflow['decision_id']}/tamper", json={"agent": "nobody"}
    )
    assert response.status_code == 400


def test_verify_on_an_unknown_decision_is_a_404(client):
    assert client.get("/api/decisions/DEC-nope/verify").status_code == 404


def test_approval_is_recorded(client, workflow):
    response = client.post(
        f"/api/decisions/{workflow['decision_id']}/approve",
        json={"approved": True, "analyst": "analyst@soc", "comment": "confirmed"},
    )
    assert response.status_code == 200
    assert response.json()["decision_id"] == workflow["decision_id"]


def test_approval_requires_an_analyst_name(client, workflow):
    """An unattributed approval is not an approval."""
    response = client.post(
        f"/api/decisions/{workflow['decision_id']}/approve",
        json={"approved": True, "analyst": ""},
    )
    assert response.status_code == 422


def test_approving_an_unknown_decision_is_a_404(client):
    response = client.post(
        "/api/decisions/DEC-nope/approve", json={"approved": True, "analyst": "a"}
    )
    assert response.status_code == 404


def test_anchoring_without_a_chain_still_returns_a_result(client, workflow):
    """§13.3: an unreachable chain degrades the proof panel, it does not 500."""
    response = client.post(f"/api/decisions/{workflow['decision_id']}/anchor")
    assert response.status_code == 200
    assert "chain_available" in response.json()


# --- metrics ---------------------------------------------------------------------------------

def test_metrics_are_served(client):
    body = client.get("/api/metrics").json()
    assert set(body) == {"baseline", "evaluation", "graph", "index"}


def test_openapi_schema_is_generated(client):
    """The frontend's types come from here, so it has to be valid."""
    schema = client.get("/openapi.json").json()
    assert "/api/workflows" in schema["paths"]
    assert "TriageOutput" in schema["components"]["schemas"]
