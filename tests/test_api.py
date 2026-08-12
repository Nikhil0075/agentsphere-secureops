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


def test_dataset_summary_never_opens_a_live_chain_client(client, monkeypatch):
    from app.api.state import AppState

    monkeypatch.setattr(
        AppState,
        "chain",
        lambda self: (_ for _ in ()).throw(AssertionError("dataset attempted an RPC connection")),
    )
    assert client.get("/api/dataset").status_code == 200


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


def test_paginated_queue_returns_total_facets_and_stable_pages(client):
    first = client.get(
        "/api/incidents/query",
        params={"limit": 5, "offset": 0, "sort_by": "risk", "sort_dir": "desc"},
    ).json()
    second = client.get(
        "/api/incidents/query",
        params={"limit": 5, "offset": 5, "sort_by": "risk", "sort_dir": "desc"},
    ).json()
    assert first["total"] >= len(first["items"])
    assert first["facets"]["categories"]
    assert {row["incident_id"] for row in first["items"]}.isdisjoint(
        {row["incident_id"] for row in second["items"]}
    )


@pytest.mark.parametrize(
    ("sort_by", "field"),
    [
        ("alerts", "alert_count"),
        ("evidence", "evidence_count"),
        ("baseline_confidence", "baseline_confidence"),
        ("incident", "incident_id"),
    ],
)
def test_paginated_queue_sorts_the_whole_result_set(client, sort_by, field):
    body = client.get(
        "/api/incidents/query",
        params={"limit": 25, "sort_by": sort_by, "sort_dir": "asc"},
    ).json()
    values = [row[field] for row in body["items"]]
    assert values == sorted(values)


def test_paginated_queue_filters_demo_and_risk(client):
    body = client.get(
        "/api/incidents/query",
        params={"showcase_only": True, "min_risk": 0.5, "limit": 100},
    ).json()
    assert body["items"]
    assert all(row["is_showcase"] and row["risk_score"] >= 0.5 for row in body["items"])


# --- the six-case presentation arc ------------------------------------------------------------
# The arc is presentation-only. These tests pin the properties the demo depends on: it is ranked,
# it is a strict subset of the showcase pool, and asking for it never changes what the pool returns.


def _arc(client) -> list[dict]:
    return client.get(
        "/api/incidents/query",
        params={"demo_only": True, "sort_by": "demo_rank", "sort_dir": "asc", "limit": 100},
    ).json()["items"]


def test_the_demo_arc_is_ranked_and_a_subset_of_the_showcase(client):
    items = _arc(client)
    if not items:
        pytest.skip("corpus prepared without a demo arc; rerun scripts/prepare_data.py")

    ranks = [row["demo_rank"] for row in items]
    assert ranks == sorted(ranks)
    assert all(row["is_showcase"] for row in items), "an arc case is outside the showcase pool"
    assert all(row["demo_role"] for row in items)
    assert len({row["demo_role"] for row in items}) == len(items)


def test_the_demo_arc_is_narrated_highest_risk_first(client):
    items = _arc(client)
    if not items:
        pytest.skip("corpus prepared without a demo arc")
    risks = [row["risk_score"] for row in items]
    assert risks == sorted(risks, reverse=True)


def test_the_demo_arc_spans_all_three_labels(client):
    items = _arc(client)
    if not items:
        pytest.skip("corpus prepared without a demo arc")
    assert len({row["label"] for row in items}) == 3


def test_requesting_the_arc_does_not_shrink_the_showcase_pool(client):
    """Two layers, two filters. `demo_only` must not leak into `showcase_only`."""
    pool = client.get(
        "/api/incidents/query", params={"showcase_only": True, "limit": 100}
    ).json()
    arc = _arc(client)
    if not arc:
        pytest.skip("corpus prepared without a demo arc")
    assert pool["total"] > len(arc)
    assert {row["incident_id"] for row in arc} <= {row["incident_id"] for row in pool["items"]}


def test_off_arc_rows_report_a_null_rank(client):
    body = client.get("/api/incidents/query", params={"limit": 100}).json()
    off_arc = [row for row in body["items"] if not row["demo_role"]]
    assert off_arc, "expected the unranked majority of the corpus in an unfiltered page"
    assert all(row["demo_rank"] is None for row in off_arc)


def test_dataset_reports_the_arc_state(client):
    body = client.get("/api/dataset").json()
    arc = body["demo_arc"]
    assert arc["expected"] == 6
    assert arc["complete"] is (arc["size"] == arc["expected"])
    assert len(arc["roles"]) == arc["size"]


def test_workflow_request_rejects_conflicting_mode_and_legacy_backend(client, incident_id):
    response = client.post(
        "/api/workflows",
        json={"incident_id": incident_id, "mode": "live", "backend": "cache"},
    )
    assert response.status_code == 422


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


def test_anchor_retry_recovers_an_existing_content_addressed_decision(
    client, workflow, monkeypatch
):
    """A lost receipt and approve-first ordering recover and finalize the existing proof."""
    from app.api.state import AppState
    from app.blockchain.client import AnchorResult, load_deployment

    deployment = load_deployment() or {}
    proof_address = (deployment.get("contracts", {}).get("DecisionProof") or {}).get(
        "address", "0x" + "22" * 20
    )

    # Reproduce the UI ordering that exposed the defect: approve in Workflow, then anchor in Proof.
    client.post(
        f"/api/decisions/{workflow['decision_id']}/approve",
        json={"approved": True, "analyst": "analyst@soc", "comment": "confirmed"},
    )

    class RecoveredChain:
        available = True

        def __init__(self):
            self.state = "proposed"
            self.approval_calls = 0
            self.finalize_calls = 0

        def submit_decision(self, **kwargs):
            return AnchorResult(
                anchored=True,
                decision_id=21,
                chain_id=11155111,
                contract_address=proof_address,
                agent_address="0x" + "33" * 20,
                onchain_state=self.state,
            )

        def approve_decision(self, decision_id, approved, comment_hash):
            self.approval_calls += 1
            self.state = "approved" if approved else "rejected"
            return AnchorResult(anchored=True, decision_id=decision_id, onchain_state=self.state)

        def finalize_decision(self, decision_id):
            self.finalize_calls += 1
            self.state = "finalized"
            return AnchorResult(anchored=True, decision_id=decision_id, onchain_state=self.state)

        def verify(self, decision_id, evidence_hash, output_hash):
            return decision_id == 21

        def find_by_fingerprint(self, incident_id, evidence_hash, output_hash):
            return 21

        def get_decision(self, decision_id):
            return {
                "incident_id": workflow["incident_id"],
                "evidence_hash": workflow["evidence_hash"],
                "output_hash": workflow["output_hash"],
                "label": workflow["triage"]["label"],
                "risk": workflow["gate"]["action_risk"],
                "state": self.state,
                "agent": "0x" + "33" * 20,
                "approver": "0x" + "00" * 20,
                "comment_hash": "0x" + "00" * 32,
                "submitted_at": 1,
                "decided_at": 0,
                "finalized_at": 0,
            }

    recovered = RecoveredChain()
    monkeypatch.setattr(AppState, "chain", lambda self: recovered)

    body = client.post(f"/api/decisions/{workflow['decision_id']}/anchor").json()

    assert body["anchored"] is True
    assert body["onchain_decision_id"] == 21
    assert body["tx_hash"] == ""
    assert body["onchain_state"] == "finalized"
    assert body["attempts"][-1]["onchain_state"] == "finalized"
    assert body["reason"] == ""
    assert recovered.approval_calls == 1
    assert recovered.finalize_calls == 1


# --- metrics ---------------------------------------------------------------------------------

@pytest.fixture
def successful_proof(client, workflow):
    """Turn the suite's offline anchor attempt into a recorded successful test transaction."""
    from app.db import session as db

    decision_id = workflow["decision_id"]
    client.post(f"/api/decisions/{decision_id}/anchor")
    with db.session() as conn:
        row = conn.execute(
            """SELECT proof_id, tx_hash, onchain_state FROM blockchain_proofs
               WHERE decision_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (decision_id,),
        ).fetchone()
        assert row is not None
        proof_id, previous_tx, previous_state = row
        conn.execute(
            "UPDATE blockchain_proofs SET tx_hash = ?, onchain_state = ? WHERE proof_id = ?",
            ("0x" + "ab" * 32, "submitted", proof_id),
        )

    yield decision_id

    with db.session() as conn:
        conn.execute(
            "UPDATE blockchain_proofs SET tx_hash = ?, onchain_state = ? WHERE proof_id = ?",
            (previous_tx, previous_state, proof_id),
        )

# --- the read-only proof route -----------------------------------------------------------------
# The whole point of this endpoint is that the Proof screen can open without touching an RPC.
# `AppState.chain()` reconnects per call, so an unconditional connect on a display route puts a
# public testnet on the demo's critical path -- the failure that took this file from 4s to 55s.


def test_proof_is_readable_without_touching_the_chain(client, workflow, monkeypatch):
    """The strongest form of the claim: make chain() explode, then read the route anyway."""
    from app.api.state import AppState

    def explode(self):
        raise AssertionError("the proof route opened a chain connection")

    monkeypatch.setattr(AppState, "chain", explode)

    body = client.get(f"/api/decisions/{workflow['decision_id']}/proof").json()
    assert body["decision_id"] == workflow["decision_id"]
    assert body["found"] is True
    assert body["chain_checked"] is False
    assert body["valid"] is None, "a route that never asked must not report a verdict"


def test_proof_404s_on_an_unknown_decision(client):
    assert client.get("/api/decisions/DEC-nope/proof").status_code == 404


def test_proof_reports_the_deployment_without_a_chain(client, workflow):
    """Addresses and network come from the deployment file, not from an RPC."""
    from app.blockchain.client import load_deployment

    deployment = load_deployment() or {}
    if not deployment:
        pytest.skip("no deployment recorded")

    body = client.get(f"/api/decisions/{workflow['decision_id']}/proof").json()
    contracts = deployment.get("contracts") or {}
    assert body["network"] == deployment.get("network", "")
    assert body["chain_id"] == deployment.get("chainId")
    assert body["contract_address"] == (contracts.get("DecisionProof") or {}).get("address", "")
    assert body["registry_address"] == (contracts.get("AgentRegistry") or {}).get("address", "")


def test_proof_reports_every_anchor_attempt(client, workflow):
    """A retry after a network failure records another attempt rather than overwriting."""
    decision_id = workflow["decision_id"]
    client.post(f"/api/decisions/{decision_id}/anchor")
    client.post(f"/api/decisions/{decision_id}/anchor")

    body = client.get(f"/api/decisions/{decision_id}/proof").json()
    assert len(body["attempts"]) >= 2
    assert len({attempt["proof_id"] for attempt in body["attempts"]}) == len(body["attempts"])


def test_anchoring_records_a_gas_column(client, workflow):
    """gas_used is on AnchorResult and was being dropped for want of a column."""
    from app.db import session as db

    decision_id = workflow["decision_id"]
    client.post(f"/api/decisions/{decision_id}/anchor")
    with db.session() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(blockchain_proofs)")}
    assert "gas_used" in columns


def test_metrics_are_served(client):
    body = client.get("/api/metrics").json()
    assert set(body) == {
        "baseline",
        "evaluation",
        "graph",
        "index",
        "proofs",
        "witfoo",
        "variance",
        "rehearsal",
    }


def test_metrics_expose_variance_and_rehearsal(client):
    """Key presence, not truthiness -- a fresh clone has neither artifact and serves {}."""
    body = client.get("/api/metrics").json()
    assert isinstance(body["variance"], dict)
    assert isinstance(body["rehearsal"], dict)


def test_metrics_report_the_proof_validity_rate(client, successful_proof):
    """§13.2: the share of completed cases whose digests still verify.

    Computed by re-verifying every anchored decision, so it reflects the database as it is now
    rather than a counter incremented at write time.
    """
    proofs = client.get("/api/metrics").json()["proofs"]

    assert proofs["decisions"] >= 1
    assert proofs["anchored"] >= 1
    assert proofs["validity_rate"] is not None
    assert 0.0 <= proofs["validity_rate"] <= 1.0
    assert proofs["verification_scope"] == "local"


def test_a_tampered_decision_shows_up_in_the_metrics(client, successful_proof):
    decision_id = successful_proof
    client.post(f"/api/decisions/{decision_id}/restore")

    before = client.get("/api/metrics").json()["proofs"]
    client.post(f"/api/decisions/{decision_id}/tamper", json={"agent": "triage"})
    after = client.get("/api/metrics").json()["proofs"]

    assert after["tampered"] > before["tampered"]
    assert after["validity_rate"] < 1.0

    client.post(f"/api/decisions/{decision_id}/restore")


def test_metrics_never_connects_to_the_chain(client, monkeypatch):
    from app.api.state import AppState

    def fail_if_called(_self):
        raise AssertionError("the aggregate metrics route must not contact the chain")

    monkeypatch.setattr(AppState, "chain", fail_if_called)
    assert client.get("/api/metrics").status_code == 200


def test_failed_anchor_attempt_does_not_count_as_anchored(client, workflow):
    from app.db import session as db

    before = client.get("/api/metrics").json()["proofs"]["anchored"]
    client.post(f"/api/decisions/{workflow['decision_id']}/anchor")
    with db.session() as conn:
        row = conn.execute(
            """SELECT proof_id, tx_hash, onchain_state FROM blockchain_proofs
               WHERE decision_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (workflow["decision_id"],),
        ).fetchone()
        assert row is not None
        proof_id, previous_tx, previous_state = row
        conn.execute(
            "UPDATE blockchain_proofs SET tx_hash = ?, onchain_state = ? WHERE proof_id = ?",
            ("0x" + "ff" * 32, "failed", proof_id),
        )
    try:
        after = client.get("/api/metrics").json()["proofs"]["anchored"]
        assert after == before
    finally:
        with db.session() as conn:
            conn.execute(
                "UPDATE blockchain_proofs SET tx_hash = ?, onchain_state = ? WHERE proof_id = ?",
                (previous_tx, previous_state, proof_id),
            )


def test_anchor_retries_count_the_decision_once(client, successful_proof):
    import uuid

    from app.db import session as db

    before = client.get("/api/metrics").json()["proofs"]["anchored"]
    duplicate_id = f"PRF-test-{uuid.uuid4().hex[:12]}"
    try:
        with db.session() as conn:
            conn.execute(
                """INSERT INTO blockchain_proofs (
                       proof_id, decision_id, chain_id, contract_address, tx_hash, block_number,
                       agent_address, evidence_hash, output_hash, onchain_state, anchored_at
                   )
                   SELECT ?, decision_id, chain_id, contract_address, tx_hash, block_number,
                          agent_address, evidence_hash, output_hash, onchain_state, anchored_at
                   FROM blockchain_proofs
                   WHERE decision_id = ? AND tx_hash != ''
                   ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (duplicate_id, successful_proof),
            )
        after = client.get("/api/metrics").json()["proofs"]["anchored"]
        assert after == before
    finally:
        with db.session() as conn:
            conn.execute("DELETE FROM blockchain_proofs WHERE proof_id = ?", (duplicate_id,))


def test_openapi_schema_is_generated(client):
    """The frontend's types come from here, so it has to be valid."""
    schema = client.get("/openapi.json").json()
    assert "/api/workflows" in schema["paths"]
    assert "TriageOutput" in schema["components"]["schemas"]


def test_a_failed_anchor_keeps_its_reason_across_a_reload(client, workflow):
    """The one fact that makes a failed anchor actionable was the one fact not stored.

    ``outcome.reason`` -- "insufficient funds for gas * price + value", or whatever the chain
    said -- lived only in the POST response. Open Proof from the tab bar rather than immediately
    after anchoring, or simply reload, and the panel read "Anchor failed / no reason reported",
    which is indistinguishable from a rail that broke for an unknown cause. The reason now
    persists on the attempt row and the read-only proof route serves it back.
    """
    decision_id = workflow["decision_id"]
    posted = client.post(f"/api/decisions/{decision_id}/anchor").json()
    assert not posted["tx_hash"], "the offline fixture chain cannot anchor"
    assert posted["reason"], "the live response must carry the chain's reason"

    # A fresh read, exactly as the page performs on load. No RPC.
    reloaded = client.get(f"/api/decisions/{decision_id}/proof").json()
    assert reloaded["reason"] == posted["reason"]
    assert reloaded["attempts"][-1]["failure_reason"] == posted["reason"]


def test_a_reason_is_never_shown_beside_a_landed_transaction(client, successful_proof):
    """Otherwise the panel explains a failure that did not happen.

    The `successful_proof` fixture is the sharp case on purpose: it rewrites a *failed* attempt's
    ``tx_hash`` in place and leaves the recorded reason behind, so the row simultaneously claims
    a transaction and carries an explanation for not having one. Reading the reason off the
    aggregate proof surfaced it; reading it off the attempt that produced it does not. A reason
    belongs to its own attempt.
    """
    proof = client.get(f"/api/decisions/{successful_proof}/proof").json()
    assert proof["reason"] == ""


def test_a_lost_transaction_is_recovered_from_the_chain_and_kept(client, workflow, monkeypatch):
    """The local record can lose the only copy of a landed transaction.

    `scripts/reset_demo.py` clears the decision tables and a fresh checkout never had them, so a
    decision that resolves by fingerprint arrives with an on-chain id and nothing else: the Proof
    screen showed a dash for block and gas and offered no link. The chain still knows --
    `DecisionSubmitted` indexes the decision id -- and "Confirm against the contract" is the one
    control allowed to ask. The answer is written back so the next load needs no RPC.

    Restores the row it borrows: `workflow` is module-scoped, so leaving a transaction behind
    would silently rewrite the premise of every later test in this file.
    """
    from app.api.state import AppState
    from app.db import session as db

    decision_id = workflow["decision_id"]
    client.post(f"/api/decisions/{decision_id}/anchor")
    with db.session() as conn:
        before = conn.execute(
            """SELECT proof_id, tx_hash, block_number, gas_used, onchain_decision_id
               FROM blockchain_proofs WHERE decision_id = ?
               ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (decision_id,),
        ).fetchone()
        proof_id = before["proof_id"]
        conn.execute(
            """UPDATE blockchain_proofs SET tx_hash = '', block_number = NULL, gas_used = NULL,
                      onchain_decision_id = 21 WHERE proof_id = ?""",
            (proof_id,),
        )
        conn.commit()

    class Recovering:
        available = True

        def submission_of(self, onchain_id):
            assert onchain_id == 21
            return {"tx_hash": "0x" + "cd" * 32, "block_number": 11452312, "gas_used": 201393}

        def get_decision(self, _):
            return {}

        def verify(self, *_a, **_k):
            return None

        def find_by_fingerprint(self, *_a, **_k):
            return 21

    try:
        monkeypatch.setattr(AppState, "chain", lambda self: Recovering())
        asked = client.get(f"/api/decisions/{decision_id}/proof?check_chain=true").json()
        assert asked["block_number"] == 11452312
        assert asked["gas_used"] == 201393
        assert asked["tx_hash"] == "0x" + "cd" * 32
        assert asked["recovered"] is True

        # Written back: the next read is zero-RPC and still carries the figures.
        monkeypatch.setattr(
            AppState,
            "chain",
            lambda self: (_ for _ in ()).throw(AssertionError("proof route opened a connection")),
        )
        again = client.get(f"/api/decisions/{decision_id}/proof").json()
        assert again["block_number"] == 11452312
        assert again["tx_hash"] == "0x" + "cd" * 32
    finally:
        with db.session() as conn:
            conn.execute(
                """UPDATE blockchain_proofs SET tx_hash = ?, block_number = ?, gas_used = ?,
                          onchain_decision_id = ? WHERE proof_id = ?""",
                (
                    before["tx_hash"], before["block_number"], before["gas_used"],
                    before["onchain_decision_id"], proof_id,
                ),
            )
            conn.commit()
