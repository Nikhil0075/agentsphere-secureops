"""The application database is created correctly and holds the prepared dataset."""

from __future__ import annotations

import json

from app.db import session as db

EXPECTED_TABLES = {
    "agent_runs",
    "approvals",
    "blockchain_proofs",
    "decisions",
    "evidence",
    "incidents",
}


def test_init_creates_every_table(tmp_path):
    path = tmp_path / "test.db"
    db.init_db(path)
    assert EXPECTED_TABLES.issubset(set(db.table_names(path)))


def test_init_is_idempotent(tmp_path):
    path = tmp_path / "test.db"
    db.init_db(path)
    db.init_db(path)
    assert EXPECTED_TABLES.issubset(set(db.table_names(path)))


def test_load_dataset_round_trips(tmp_path, evidence, incident_table):
    path = tmp_path / "test.db"
    counts = db.load_dataset(incident_table, evidence, db_path=path)
    assert counts["incidents"] == len(incident_table)
    assert counts["evidence"] == len(evidence)

    with db.session(path) as conn:
        row = conn.execute(
            "SELECT payload_json FROM evidence LIMIT 1"
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert "evidence_id" in payload and "incident_id" in payload


def test_load_dataset_replaces_rather_than_appends(tmp_path, evidence, incident_table):
    path = tmp_path / "test.db"
    db.load_dataset(incident_table, evidence, db_path=path)
    counts = db.load_dataset(incident_table, evidence, db_path=path)
    assert counts["incidents"] == len(incident_table)


def test_evidence_cascade_delete(tmp_path, evidence, incident_table):
    path = tmp_path / "test.db"
    db.load_dataset(incident_table, evidence, db_path=path)
    target = incident_table["incident_id"].iloc[0]
    with db.session(path) as conn:
        conn.execute("DELETE FROM incidents WHERE incident_id = ?", (target,))
        remaining = conn.execute(
            "SELECT COUNT(*) AS n FROM evidence WHERE incident_id = ?", (target,)
        ).fetchone()["n"]
    assert remaining == 0
