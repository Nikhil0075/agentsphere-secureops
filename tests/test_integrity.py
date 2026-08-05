"""Digest recomputation and the tamper demo.

The Day 6 exit criterion is `test_tampering_with_an_agent_output_breaks_verification`. The rest
exists because the *first* version of this check was worthless: it compared a stored hash column
against the chain, so both sides came from the same write and editing an agent's output changed
neither. These tests pin the property that actually matters — the digest is recomputed from the
underlying stored data, so altering that data changes the answer.
"""

from __future__ import annotations

import json
import sqlite3

import pandas as pd
import pytest

from app.agents.schemas import AgentRunRecord
from app.blockchain.hashing import hash_evidence_bundle
from app.db import session as db
from app.db.session import canonical_evidence_payload
from app.observability.logging import persist_agent_run
from app.orchestration.workflow import Workflow
from app.services import decisions as decisions_service
from app.services import integrity


@pytest.fixture
def dataset():
    from app.data import fixture
    from app.data import incidents as incidents_mod

    evidence = fixture.generate(n_incidents=6)
    incidents = incidents_mod.aggregate(evidence)
    incidents["summary"] = "summary for testing"
    return evidence, incidents


@pytest.fixture
def anchored(tmp_path, dataset):
    """A completed workflow, persisted, with a proof row recorded. No chain needed."""
    from app.agents.llm import DeterministicClient
    from app.data import incidents as incidents_mod

    evidence, incidents = dataset
    row = incidents.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])

    result = Workflow(client=DeterministicClient()).run(row, rows)
    state = result.state

    conn = sqlite3.connect(tmp_path / "t.db")
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    db.load_dataset(incidents, evidence, db_path=tmp_path / "t.db")
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))

    for run in state.runs:
        output = getattr(state, run.agent, None)
        persist_agent_run(
            conn,
            state.workflow_id,
            state.incident_id,
            run,
            json.dumps(output.model_dump(mode="json"), sort_keys=True) if output else "",
        )

    persisted = decisions_service.save_decision(conn, result)
    conn.execute(
        """INSERT INTO blockchain_proofs (proof_id, decision_id, tx_hash, evidence_hash,
                                          output_hash, onchain_state)
           VALUES (?,?,?,?,?,?)""",
        (
            "PRF-test",
            persisted.decision_id,
            "0xdeadbeef",
            state.evidence_hash,
            state.output_hash,
            "submitted",
        ),
    )
    conn.commit()

    yield conn, persisted.decision_id, state
    conn.close()


# --- the exit criterion ------------------------------------------------------------------

def test_a_clean_record_verifies(anchored):
    conn, decision_id, _ = anchored
    report = integrity.check(conn, decision_id)
    assert report.valid is True
    assert report.tampered == []


def test_tampering_with_an_agent_output_breaks_verification(anchored):
    """Day 6 exit criterion: changing an off-chain output must fail verification."""
    conn, decision_id, state = anchored
    assert integrity.check(conn, decision_id).valid is True

    change = integrity.tamper(conn, state.workflow_id, "triage")
    report = integrity.check(conn, decision_id)

    assert change["before"] != change["after"]
    assert report.valid is False
    assert report.output_valid is False
    assert "agent output" in report.tampered
    assert report.recomputed_output_hash != report.anchored_output_hash


def test_restore_makes_it_verify_again(anchored):
    """The demo has to be repeatable; a one-shot tamper is a one-shot rehearsal."""
    conn, decision_id, state = anchored
    integrity.tamper(conn, state.workflow_id, "triage")
    assert integrity.check(conn, decision_id).valid is False

    assert integrity.restore(conn, state.workflow_id) == 1
    assert integrity.check(conn, decision_id).valid is True


def test_tampering_with_evidence_content_breaks_verification(anchored):
    """Editing an evidence row must be caught too.

    The first evidence digest covered only the *ids*, so an edit to a row's content passed
    verification and "tamper-evident evidence" was not a true claim.
    """
    conn, decision_id, state = anchored
    bundle = integrity.bundled_evidence_ids(conn, state.workflow_id)
    assert bundle

    original = conn.execute(
        "SELECT payload_json FROM evidence WHERE evidence_id = ?", (bundle[0],)
    ).fetchone()[0]
    edited = json.loads(original)
    edited["account_upn"] = "attacker-covered-this-up@contoso.com"
    conn.execute(
        "UPDATE evidence SET payload_json = ? WHERE evidence_id = ?",
        (json.dumps(edited, sort_keys=True, separators=(",", ":")), bundle[0]),
    )
    conn.commit()

    report = integrity.check(conn, decision_id)
    assert report.valid is False
    assert report.evidence_valid is False
    assert "evidence" in report.tampered


def test_deleting_an_evidence_row_is_detected(anchored):
    """Removal is a form of tampering that a naive id-only digest would miss entirely."""
    conn, decision_id, state = anchored
    bundle = integrity.bundled_evidence_ids(conn, state.workflow_id)
    conn.execute("DELETE FROM evidence WHERE evidence_id = ?", (bundle[0],))
    conn.commit()
    assert integrity.check(conn, decision_id).evidence_valid is False


# --- recomputation is real ----------------------------------------------------------------

def test_the_check_never_reads_the_stored_hash_column(anchored):
    """Corrupting decisions.output_hash must not change the verdict.

    That column is a display cache. If the check consulted it, an attacker who edited both the
    output and the cache would verify clean — which is exactly the hole this replaced.
    """
    conn, decision_id, _ = anchored
    conn.execute(
        "UPDATE decisions SET output_hash = ?, evidence_hash = ?",
        ("0x" + "00" * 32, "0x" + "00" * 32),
    )
    conn.commit()
    assert integrity.check(conn, decision_id).valid is True


def test_recomputed_hash_matches_what_the_workflow_produced(anchored):
    conn, _, state = anchored
    assert integrity.recompute_output_hash(conn, state.workflow_id) == state.output_hash


def test_recomputed_evidence_hash_matches_what_the_workflow_produced(anchored):
    conn, _, state = anchored
    bundle = integrity.bundled_evidence_ids(conn, state.workflow_id)
    recomputed = integrity.recompute_evidence_hash(conn, state.incident_id, bundle)
    assert recomputed == state.evidence_hash


def test_recomputation_is_stable_across_calls(anchored):
    conn, _, state = anchored
    a = integrity.recompute_output_hash(conn, state.workflow_id)
    b = integrity.recompute_output_hash(conn, state.workflow_id)
    assert a == b


def test_unparseable_output_changes_the_digest_rather_than_vanishing(anchored):
    """A payload that no longer parses is itself a tamper signal."""
    conn, decision_id, state = anchored
    conn.execute(
        "UPDATE agent_runs SET output_json = ? WHERE workflow_id = ? AND agent = 'triage'",
        ("{not json", state.workflow_id),
    )
    conn.commit()
    assert integrity.check(conn, decision_id).output_valid is False


def test_an_unanchored_decision_reports_nothing_to_verify_against(tmp_path, dataset):
    from app.agents.llm import DeterministicClient
    from app.data import incidents as incidents_mod

    evidence, incidents = dataset
    row = incidents.iloc[0]
    result = Workflow(client=DeterministicClient()).run(
        row, incidents_mod.evidence_for(evidence, row["incident_id"])
    )

    conn = sqlite3.connect(tmp_path / "u.db")
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    db.load_dataset(incidents, evidence, db_path=tmp_path / "u.db")
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    persisted = decisions_service.save_decision(conn, result)

    report = integrity.check(conn, persisted.decision_id)
    assert report.valid is None
    assert "not been anchored" in report.detail
    conn.close()


def test_unknown_decision_is_reported_not_raised(anchored):
    conn, _, _ = anchored
    report = integrity.check(conn, "DEC-nope")
    assert report.found is False


# --- the evidence content digest ------------------------------------------------------------

def test_evidence_digest_covers_content_not_only_ids():
    ids = ["EVD-1", "EVD-2"]
    a = hash_evidence_bundle(ids, "INC-1", payloads={"EVD-1": '{"x":1}', "EVD-2": '{"y":2}'})
    b = hash_evidence_bundle(ids, "INC-1", payloads={"EVD-1": '{"x":999}', "EVD-2": '{"y":2}'})
    assert a != b


def test_evidence_digest_is_order_independent():
    payloads = {"EVD-1": '{"x":1}', "EVD-2": '{"y":2}'}
    assert hash_evidence_bundle(["EVD-1", "EVD-2"], "INC-1", payloads=payloads) == (
        hash_evidence_bundle(["EVD-2", "EVD-1"], "INC-1", payloads=payloads)
    )


def test_content_digest_differs_from_the_id_only_digest():
    """The weaker form is still reachable, so it must not be mistaken for the strong one."""
    ids = ["EVD-1"]
    assert hash_evidence_bundle(ids, "INC-1") != hash_evidence_bundle(
        ids, "INC-1", payloads={"EVD-1": '{"x":1}'}
    )


def test_writer_and_verifier_share_one_serialiser():
    """Two independent serialisations differing by a space would read as tampering forever."""
    row = {"evidence_id": "EVD-1", "value": 1, "when": pd.Timestamp("2026-08-09T10:00:00Z")}
    rendered = canonical_evidence_payload(row)

    assert rendered == canonical_evidence_payload(dict(row))
    # Separators carry no whitespace. Values legitimately can — a timestamp renders with a space
    # inside the string — so check the separators rather than the whole document.
    assert ", " not in rendered and '": ' not in rendered
    # Key order must not depend on insertion order.
    assert rendered == canonical_evidence_payload(dict(reversed(list(row.items()))))


# --- the tamper itself -------------------------------------------------------------------

def test_tamper_changes_a_field_a_human_can_see(anchored):
    """A random byte flip proves the same thing but shows nothing on screen."""
    conn, _, state = anchored
    change = integrity.tamper(conn, state.workflow_id, "triage")
    assert change["field"] == "label"
    assert change["before"] in {"TruePositive", "BenignPositive", "FalsePositive"}
    assert change["after"] != change["before"]


def test_tamper_leaves_the_chain_untouched(anchored):
    """It edits the operator's database and nothing else — that is the whole argument."""
    conn, decision_id, state = anchored
    before = conn.execute(
        "SELECT output_hash, tx_hash FROM blockchain_proofs WHERE decision_id = ?",
        (decision_id,),
    ).fetchone()
    integrity.tamper(conn, state.workflow_id, "triage")
    after = conn.execute(
        "SELECT output_hash, tx_hash FROM blockchain_proofs WHERE decision_id = ?",
        (decision_id,),
    ).fetchone()
    assert before == after


def test_tamper_is_available_for_several_agents(anchored):
    conn, decision_id, state = anchored
    for agent in ("triage", "remediation", "verifier", "detection"):
        integrity.restore(conn, state.workflow_id)
        change = integrity.tamper(conn, state.workflow_id, agent)
        assert change["agent"] == agent
        assert integrity.check(conn, decision_id).valid is False


def test_tampering_an_unknown_agent_raises(anchored):
    conn, _, state = anchored
    with pytest.raises(ValueError):
        integrity.tamper(conn, state.workflow_id, "nonexistent")


def test_restore_with_nothing_to_restore_is_a_no_op(anchored):
    conn, _, state = anchored
    assert integrity.restore(conn, state.workflow_id) == 0


def test_the_report_flags_that_a_tamper_is_active(anchored):
    conn, decision_id, state = anchored
    assert integrity.check(conn, decision_id).tamper_active is False
    integrity.tamper(conn, state.workflow_id, "triage")
    assert integrity.check(conn, decision_id).tamper_active is True


def test_the_verdict_does_not_depend_on_the_tamper_log(anchored):
    """The log is a rehearsal aid. Deleting it must not make a tampered record verify clean."""
    conn, decision_id, state = anchored
    integrity.tamper(conn, state.workflow_id, "triage")
    conn.execute("DELETE FROM tamper_log")
    conn.commit()
    assert integrity.check(conn, decision_id).valid is False
