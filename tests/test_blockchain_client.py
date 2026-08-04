"""The Python chain client and decision persistence.

The behaviour under test that matters most is **graceful degradation**. §13.3 lists network
failure during judging as a live risk, and the mitigation is that an unreachable chain downgrades
the proof panel rather than taking the demo down. Every method here must return a reported
outcome, never raise.

The contract logic itself is tested in contracts/test/DecisionProof.test.ts against a real EVM;
duplicating it with mocks here would test the mocks.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from app.blockchain.client import (
    ENUM_TO_RISK,
    RISK_TO_ENUM,
    STATE_NAMES,
    AnchorResult,
    ChainClient,
    load_deployment,
)
from app.blockchain.hashing import hash_payload
from app.db import session as db
from app.services import decisions
from tests.fixtures import scenarios


@pytest.fixture
def conn(tmp_path):
    connection = sqlite3.connect(tmp_path / "test.db")
    connection.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.execute(
        "INSERT INTO incidents (incident_id, label, alert_count, evidence_count) VALUES (?,?,?,?)",
        ("INC-truepositive", "TruePositive", 2, 8),
    )
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def result():
    from app.orchestration.context import IncidentContext
    from app.orchestration.workflow import WorkflowResult

    state = scenarios.true_positive()
    state.evidence_hash = hash_payload({"evidence": "bundle"})
    state.output_hash = hash_payload({"outputs": "agents"})
    context = IncidentContext(
        incident_id=state.incident_id, summary="", evidence=None, incident_fields={}
    )
    return WorkflowResult(state=state, context=context)


# --- degradation ---------------------------------------------------------------------------

def test_a_missing_deployment_is_unavailable_not_an_exception(tmp_path):
    client = ChainClient.connect(tmp_path / "nope.json")
    assert not client.available
    assert "no deployment" in client.unavailable_reason


def test_an_unreachable_rpc_is_unavailable_not_an_exception(tmp_path):
    deployment = tmp_path / "deployment.json"
    deployment.write_text(
        json.dumps(
            {
                "network": "localhost",
                "chainId": 31337,
                "contracts": {
                    "AgentRegistry": {"address": "0x" + "11" * 20, "abi": []},
                    "DecisionProof": {"address": "0x" + "22" * 20, "abi": []},
                },
            }
        ),
        encoding="utf-8",
    )
    # Port 1 is reserved and never listening.
    client = ChainClient.connect(deployment, rpc_url="http://127.0.0.1:1")
    assert not client.available


def test_every_write_returns_a_result_rather_than_raising(tmp_path):
    """The demo must survive an unplugged network."""
    client = ChainClient.connect(tmp_path / "nope.json")

    submit = client.submit_decision("INC-1", "0xaa", "0xbb", "TruePositive", "high")
    approve = client.approve_decision(1, True, "0xcc")
    finalize = client.finalize_decision(1)

    for outcome in (submit, approve, finalize):
        assert isinstance(outcome, AnchorResult)
        assert not outcome.anchored
        assert outcome.reason


def test_reads_return_none_when_the_chain_is_unavailable(tmp_path):
    client = ChainClient.connect(tmp_path / "nope.json")
    assert client.get_decision(1) is None
    assert client.verify(1, "0xaa", "0xbb") is None


def test_status_is_reportable_even_when_unavailable(tmp_path):
    status = ChainClient.connect(tmp_path / "nope.json").status()
    assert status["available"] is False
    assert status["reason"]


def test_a_malformed_deployment_file_does_not_crash(tmp_path):
    bad = tmp_path / "deployment.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_deployment(bad) is None
    assert not ChainClient.connect(bad).available


# --- encodings shared with Solidity ------------------------------------------------------

def test_risk_enum_matches_the_solidity_ordering():
    """Low=0, Medium=1, High=2. Getting this wrong silently mislabels every anchored decision."""
    assert RISK_TO_ENUM == {"low": 0, "medium": 1, "high": 2}
    assert ENUM_TO_RISK[2] == "high"


def test_state_names_match_the_solidity_enum():
    assert STATE_NAMES == {0: "proposed", 1: "approved", 2: "rejected", 3: "finalized"}


def test_hash_conversion_accepts_prefixed_and_bare_hex():
    digest = hash_payload({"a": 1})
    assert ChainClient._to_bytes32(digest) == ChainClient._to_bytes32(digest[2:])
    assert len(ChainClient._to_bytes32(digest)) == 32


def test_explorer_url_is_built_for_sepolia_only():
    sepolia = AnchorResult(anchored=True, tx_hash="0xabc", chain_id=11155111)
    local = AnchorResult(anchored=True, tx_hash="0xabc", chain_id=31337)
    assert "sepolia.etherscan.io" in sepolia.explorer_url
    assert local.explorer_url == ""


def test_anchor_result_serialises_for_the_api():
    payload = AnchorResult(anchored=False, reason="no chain").as_dict()
    assert payload["anchored"] is False
    assert "explorer_url" in payload
    assert payload["blocked_by_policy"] is False


# --- custom error decoding ---------------------------------------------------------------

def _client_with_abi() -> ChainClient:
    """A client bound to the real error ABI, without needing a chain."""
    client = ChainClient(
        deployment={
            "chainId": 11155111,
            "contracts": {
                "DecisionProof": {
                    "address": "0x" + "22" * 20,
                    "abi": [
                        {
                            "type": "error",
                            "name": "ApprovalRequired",
                            "inputs": [{"name": "decisionId", "type": "uint256"}],
                        },
                        {
                            "type": "error",
                            "name": "UnauthorisedAgent",
                            "inputs": [{"name": "caller", "type": "address"}],
                        },
                    ],
                }
            },
        }
    )
    client._error_selectors = client._build_error_selectors()
    return client


def test_approval_required_selector_matches_the_real_chain():
    """0xb0be42d3 is what Sepolia actually returned for ApprovalRequired(uint256).

    Public RPCs return raw revert data, so matching on the error *name* in an exception string
    works against a local Hardhat node and silently stops working on a real testnet.
    """
    client = _client_with_abi()
    assert client._error_selectors["0xb0be42d3"] == "ApprovalRequired"


def test_a_raw_revert_payload_decodes_to_the_error_name():
    client = _client_with_abi()
    raw = (
        "ContractCustomError: ('0xb0be42d30000000000000000000000000000000000000000"
        "000000000000000000000001',)"
    )
    assert client._decode_error(raw) == "ApprovalRequired"


def test_a_decoded_provider_message_still_matches():
    """Hardhat decodes it for us; both shapes must work."""
    client = _client_with_abi()
    assert client._decode_error("reverted with custom error 'ApprovalRequired(1)'") == (
        "ApprovalRequired"
    )


def test_an_unrelated_failure_decodes_to_nothing():
    client = _client_with_abi()
    assert client._decode_error("ConnectionError: RPC timed out") == ""


def test_a_policy_block_is_distinguished_from_a_real_failure():
    """A high-risk decision failing to finalise is the control working, not an error, and the
    demo has to say so in those words."""
    blocked = AnchorResult(anchored=False, error="ApprovalRequired", reason="…")
    broken = AnchorResult(anchored=False, error="", reason="ConnectionError")

    assert blocked.blocked_by_policy
    assert not broken.blocked_by_policy


def test_unauthorised_agent_also_counts_as_a_policy_block():
    assert AnchorResult(anchored=False, error="UnauthorisedAgent").blocked_by_policy


def test_selectors_are_built_from_every_deployed_contract():
    from app.blockchain.client import load_deployment

    deployment = load_deployment()
    if deployment is None:
        pytest.skip("no deployment recorded")
    client = ChainClient(deployment=deployment)
    selectors = client._build_error_selectors()
    assert "ApprovalRequired" in selectors.values()
    assert "UnauthorisedAgent" in selectors.values()
    assert all(s.startswith("0x") and len(s) == 10 for s in selectors)


# --- persistence ----------------------------------------------------------------------------

def test_a_decision_is_persisted_with_its_hashes(conn, result):
    persisted = decisions.save_decision(conn, result)
    row = conn.execute(
        "SELECT label, action_risk, evidence_hash, output_hash, state FROM decisions WHERE decision_id = ?",
        (persisted.decision_id,),
    ).fetchone()
    assert row[0] == "TruePositive"
    assert row[2] == result.state.evidence_hash
    assert row[4] == "proposed"


def test_an_approval_is_recorded_and_moves_the_decision_state(conn, result):
    persisted = decisions.save_decision(conn, result)
    decisions.record_approval(conn, persisted.decision_id, "analyst@soc", True, "looks right")

    state = conn.execute(
        "SELECT state FROM decisions WHERE decision_id = ?", (persisted.decision_id,)
    ).fetchone()[0]
    assert state == "approved"


def test_a_rejection_is_recorded_too(conn, result):
    persisted = decisions.save_decision(conn, result)
    decisions.record_approval(conn, persisted.decision_id, "analyst@soc", False, "no")
    state = conn.execute(
        "SELECT state FROM decisions WHERE decision_id = ?", (persisted.decision_id,)
    ).fetchone()[0]
    assert state == "rejected"


def test_the_approver_comment_stays_off_chain(conn, result):
    """Only the hash may leave. The comment itself is application data (§4.3)."""
    persisted = decisions.save_decision(conn, result)
    secret = "contains an analyst's private note about a named employee"
    decisions.record_approval(conn, persisted.decision_id, "analyst@soc", True, secret)

    comment, comment_hash = conn.execute(
        "SELECT comment, comment_hash FROM approvals WHERE decision_id = ?",
        (persisted.decision_id,),
    ).fetchone()
    assert comment == secret
    assert secret not in comment_hash
    assert comment_hash.startswith("0x") and len(comment_hash) == 66


def test_anchoring_without_a_chain_still_records_the_attempt(conn, result, tmp_path):
    """An unanchored proof row is a truthful record: we tried, and there was no chain."""
    persisted = decisions.save_decision(conn, result)
    client = ChainClient.connect(tmp_path / "nope.json")
    outcome = decisions.anchor_decision(conn, persisted.decision_id, result, client)

    assert not outcome.anchored
    state = conn.execute(
        "SELECT onchain_state FROM blockchain_proofs WHERE decision_id = ?",
        (persisted.decision_id,),
    ).fetchone()[0]
    assert state == "unanchored"


def test_verify_reports_not_found_for_an_unknown_decision(conn, tmp_path):
    client = ChainClient.connect(tmp_path / "nope.json")
    assert decisions.verify_decision(conn, "DEC-nope", client)["found"] is False


def test_the_persisted_decision_carries_the_gate_outcome(conn, result):
    from app.policies import engine

    result.gate = engine.evaluate(
        triage=result.state.triage,
        remediation=result.state.remediation,
        verifier=None,
        evidence_ids=result.state.correlation.evidence_bundle,
    )
    persisted = decisions.save_decision(conn, result)
    requires = conn.execute(
        "SELECT requires_approval FROM decisions WHERE decision_id = ?",
        (persisted.decision_id,),
    ).fetchone()[0]
    assert requires == int(result.state.requires_approval)


def test_nothing_but_digests_would_reach_the_chain(conn, result):
    """Guard on the §4.3 boundary: the anchoring payload carries no evidence content."""
    captured = {}

    class Recorder:
        available = True
        chain_id = 31337
        contract_address = "0x" + "33" * 20

        def submit_decision(self, **kwargs):
            captured.update(kwargs)
            return AnchorResult(anchored=True, decision_id=1, tx_hash="0xdead")

    persisted = decisions.save_decision(conn, result)
    decisions.anchor_decision(conn, persisted.decision_id, result, Recorder())

    assert set(captured) == {"incident_id", "evidence_hash", "output_hash", "label", "risk"}
    blob = json.dumps(captured)
    assert result.state.triage.rationale not in blob
    assert result.state.remediation.justification not in blob
