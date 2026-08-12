"""The demo reset, and the one guarantee it has to keep.

Clearing the local tables destroys the only local record of what was anchored, but the chain
remembers every fingerprint for ever. If the ledger did not survive the reset, the script would
start recommending already-anchored incidents as "fresh" on the second run — and the demo it
exists to enable would silently stop producing transactions.
"""

from __future__ import annotations

import json

import pytest

from scripts import reset_demo


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    path = tmp_path / "anchored_incidents.json"
    monkeypatch.setattr(reset_demo, "LEDGER", path)
    return path


def test_the_ledger_round_trips(ledger):
    reset_demo.save_ledger({"INC-b", "INC-a"})
    assert reset_demo.load_ledger() == {"INC-a", "INC-b"}
    # Sorted on disk so a reset produces no spurious diff.
    assert json.loads(ledger.read_text(encoding="utf-8"))["incident_ids"] == ["INC-a", "INC-b"]


def test_an_absent_or_corrupt_ledger_is_empty_rather_than_fatal(ledger):
    assert reset_demo.load_ledger() == set()
    ledger.write_text("{not json", encoding="utf-8")
    assert reset_demo.load_ledger() == set()


def test_the_ledger_accumulates_across_resets(ledger):
    """The second reset must not forget what the first one cleared."""
    reset_demo.save_ledger({"INC-a"})
    reset_demo.save_ledger(reset_demo.load_ledger() | {"INC-b"})
    assert reset_demo.load_ledger() == {"INC-a", "INC-b"}


def test_only_attempts_that_reached_the_contract_count_as_anchored(tmp_path):
    """A refused submission leaves a row but no on-chain record, so the incident is still fresh."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE decisions (decision_id TEXT, incident_id TEXT);
        CREATE TABLE blockchain_proofs (
            decision_id TEXT, tx_hash TEXT, onchain_decision_id INTEGER
        );
        INSERT INTO decisions VALUES ('D1','INC-landed'), ('D2','INC-refused');
        INSERT INTO blockchain_proofs VALUES ('D1','0xabc', 12);
        INSERT INTO blockchain_proofs VALUES ('D2','', NULL);
        """
    )
    assert reset_demo.anchored_incidents(conn) == {"INC-landed"}
