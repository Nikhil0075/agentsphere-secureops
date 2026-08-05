"""Recompute decision digests from stored data and compare them with what was anchored.

This is the module the whole Web3 claim rests on, and it exists because the first version of the
check did not actually check anything: it read the ``decisions.evidence_hash`` column and compared
it to the chain. Both sides of that comparison come from the same write, so editing an agent's
stored output left verification passing. A tamper button on top of that would have been theatre.

What happens here instead:

* the output digest is **recomputed from ``agent_runs.output_json``** — the actual stored agent
  outputs, reassembled in contract order exactly as the workflow assembled them;
* the evidence digest is **recomputed from ``evidence.payload_json``** — the actual stored
  evidence content, for the ids the Correlation agent bundled;
* those recomputed digests are compared with the digests recorded on chain.

So a mismatch means the off-chain record changed after anchoring. That is the only claim worth
making, and now it is the one being tested.

Nothing here trusts a stored hash column. The columns remain, but only as a cache for display —
:func:`check` never reads them for the verdict.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from app.agents.schemas import AGENT_OUTPUT_MODELS
from app.blockchain.client import ChainClient
from app.blockchain.hashing import hash_agent_output, hash_evidence_bundle

#: Agent order the workflow hashes in. Must match ``workflow.AGENT_SEQUENCE``.
AGENT_ORDER = tuple(AGENT_OUTPUT_MODELS)


@dataclass
class IntegrityReport:
    decision_id: str
    found: bool = False
    workflow_id: str = ""
    incident_id: str = ""

    anchored_evidence_hash: str = ""
    anchored_output_hash: str = ""
    recomputed_evidence_hash: str = ""
    recomputed_output_hash: str = ""

    evidence_valid: bool | None = None
    output_valid: bool | None = None
    onchain_valid: bool | None = None

    tampered: list[str] = field(default_factory=list)
    tamper_active: bool = False
    chain_available: bool = False
    tx_hash: str = ""
    onchain_decision_id: int | None = None
    detail: str = ""

    @property
    def valid(self) -> bool | None:
        """``None`` when there is nothing anchored to compare against."""
        if self.evidence_valid is None and self.output_valid is None:
            return None
        return bool(self.evidence_valid) and bool(self.output_valid)

    def as_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "found": self.found,
            "workflow_id": self.workflow_id,
            "incident_id": self.incident_id,
            "anchored_evidence_hash": self.anchored_evidence_hash,
            "anchored_output_hash": self.anchored_output_hash,
            "recomputed_evidence_hash": self.recomputed_evidence_hash,
            "recomputed_output_hash": self.recomputed_output_hash,
            "evidence_valid": self.evidence_valid,
            "output_valid": self.output_valid,
            "onchain_valid": self.onchain_valid,
            "valid": self.valid,
            "tampered": self.tampered,
            "tamper_active": self.tamper_active,
            "chain_available": self.chain_available,
            "tx_hash": self.tx_hash,
            "onchain_decision_id": self.onchain_decision_id,
            "detail": self.detail,
        }


# --- recomputation -----------------------------------------------------------------------

def stored_agent_outputs(conn: sqlite3.Connection, workflow_id: str) -> dict[str, dict]:
    """Agent outputs as they are stored right now, keyed by agent name.

    Reads the latest row per agent, because a re-run of the same workflow id would otherwise
    produce duplicates and a nondeterministic digest.
    """
    rows = conn.execute(
        """
        SELECT agent, output_json, MAX(created_at)
        FROM agent_runs
        WHERE workflow_id = ? AND output_json IS NOT NULL AND output_json != ''
        GROUP BY agent
        """,
        (workflow_id,),
    ).fetchall()

    outputs: dict[str, dict] = {}
    for agent, output_json, _ in rows:
        try:
            outputs[agent] = json.loads(output_json)
        except json.JSONDecodeError:
            # A payload that no longer parses is itself a tamper signal; represent it as such
            # rather than dropping it, so the digest changes instead of the agent vanishing.
            outputs[agent] = {"__unparseable__": output_json}
    return outputs


def recompute_output_hash(conn: sqlite3.Connection, workflow_id: str) -> str:
    """Rebuild the workflow output digest from stored agent outputs.

    Mirrors ``Workflow.run``: the same dict, in the same agent order, through the same hash.
    """
    outputs = stored_agent_outputs(conn, workflow_id)
    ordered = {name: outputs[name] for name in AGENT_ORDER if name in outputs}
    return hash_agent_output("workflow", ordered)


def bundled_evidence_ids(conn: sqlite3.Connection, workflow_id: str) -> list[str]:
    """The evidence ids the Correlation agent bundled, read back from its stored output."""
    outputs = stored_agent_outputs(conn, workflow_id)
    bundle = (outputs.get("correlation") or {}).get("evidence_bundle")
    if isinstance(bundle, list):
        return [str(e) for e in bundle]
    return []


def recompute_evidence_hash(
    conn: sqlite3.Connection, incident_id: str, evidence_ids: list[str]
) -> str:
    """Rebuild the evidence digest from stored evidence content."""
    if not evidence_ids:
        return hash_evidence_bundle([], incident_id, payloads={})

    placeholders = ",".join("?" * len(evidence_ids))
    rows = conn.execute(
        f"SELECT evidence_id, payload_json FROM evidence WHERE evidence_id IN ({placeholders})",
        evidence_ids,
    ).fetchall()
    payloads = {str(eid): payload or "" for eid, payload in rows}
    return hash_evidence_bundle(evidence_ids, incident_id, payloads=payloads)


# --- the check ---------------------------------------------------------------------------

def check(
    conn: sqlite3.Connection, decision_id: str, client: ChainClient | None = None
) -> IntegrityReport:
    """Recompute both digests from stored data and compare them with the anchored ones."""
    row = conn.execute(
        """
        SELECT d.workflow_id, d.incident_id, p.tx_hash, p.evidence_hash, p.output_hash,
               p.chain_id
        FROM decisions d
        LEFT JOIN blockchain_proofs p ON p.decision_id = d.decision_id
        WHERE d.decision_id = ?
        ORDER BY p.created_at DESC LIMIT 1
        """,
        (decision_id,),
    ).fetchone()
    if row is None:
        return IntegrityReport(decision_id=decision_id, found=False, detail="unknown decision")

    workflow_id, incident_id, tx_hash, anchored_evidence, anchored_output, _chain_id = row
    report = IntegrityReport(
        decision_id=decision_id,
        found=True,
        workflow_id=workflow_id or "",
        incident_id=incident_id or "",
        anchored_evidence_hash=anchored_evidence or "",
        anchored_output_hash=anchored_output or "",
        tx_hash=tx_hash or "",
    )

    report.recomputed_output_hash = recompute_output_hash(conn, workflow_id)
    report.recomputed_evidence_hash = recompute_evidence_hash(
        conn, incident_id, bundled_evidence_ids(conn, workflow_id)
    )

    report.tamper_active = bool(
        conn.execute(
            """SELECT COUNT(*) FROM tamper_log t
               JOIN agent_runs r ON r.run_id = t.run_id
               WHERE r.workflow_id = ? AND t.active = 1""",
            (workflow_id,),
        ).fetchone()[0]
    )

    if not anchored_output:
        report.detail = "decision has not been anchored, so there is nothing to verify against"
        return report

    report.evidence_valid = report.recomputed_evidence_hash == anchored_evidence
    report.output_valid = report.recomputed_output_hash == anchored_output
    if not report.evidence_valid:
        report.tampered.append("evidence")
    if not report.output_valid:
        report.tampered.append("agent output")

    # Ask the contract the same question, so the answer does not rest on our own database.
    if client is not None and client.available:
        report.chain_available = True
        onchain_id = _onchain_id(client, incident_id, anchored_evidence, anchored_output)
        report.onchain_decision_id = onchain_id
        if onchain_id:
            report.onchain_valid = client.verify(
                onchain_id,
                report.recomputed_evidence_hash,
                report.recomputed_output_hash,
            )

    report.detail = (
        "recomputed digests match the anchored proof"
        if report.valid
        else f"recomputed digests differ from the anchored proof: {', '.join(report.tampered)}"
    )
    return report


def _onchain_id(
    client: ChainClient, incident_id: str, evidence_hash: str, output_hash: str
) -> int | None:
    try:
        found = client._proof.functions.findByFingerprint(  # noqa: SLF001
            incident_id,
            client._to_bytes32(evidence_hash),
            client._to_bytes32(output_hash),
        ).call()
        return int(found) or None
    except Exception:  # noqa: BLE001 - an unreachable chain must not break verification display
        return None


# --- the demo tamper ------------------------------------------------------------------------

#: What the tamper mutates, per agent. Chosen to be visibly meaningful on screen rather than a
#: random byte flip: an analyst watching should see the *decision* change, not noise.
TAMPER_FIELDS = {
    "triage": "label",
    "remediation": "recommended_action",
    "verifier": "verdict",
    "detection": "severity_score",
}

_FLIP = {
    "TruePositive": "FalsePositive",
    "BenignPositive": "TruePositive",
    "FalsePositive": "TruePositive",
}


def tamper(conn: sqlite3.Connection, workflow_id: str, agent: str = "triage") -> dict:
    """Edit a stored agent output, the way an insider with database access would.

    Deliberately *only* touches the application database — no hash column is updated and nothing
    on chain is touched, because that is precisely the point: the operator controls this table and
    controls nothing about the anchored digest.
    """
    row = conn.execute(
        """SELECT run_id, output_json FROM agent_runs
           WHERE workflow_id = ? AND agent = ? ORDER BY created_at DESC LIMIT 1""",
        (workflow_id, agent),
    ).fetchone()
    if row is None:
        raise ValueError(f"no stored output for agent {agent!r} in workflow {workflow_id}")

    run_id, original_json = row
    payload = json.loads(original_json)
    field_name = TAMPER_FIELDS.get(agent, "")

    # Every branch must pick a value that differs from the current one. Naively writing a fixed
    # target silently no-ops whenever the field already holds it — a remediation of
    # ``close_as_false_positive`` "tampered" to ``close_as_false_positive`` changes no bytes, the
    # digest still matches, and the demo shows VALID at the moment it is meant to show TAMPERED.
    if field_name == "label":
        before = payload.get("label", "")
        payload["label"] = _FLIP.get(before, "TruePositive")
    elif field_name == "verdict":
        before = payload.get("verdict", "")
        payload["verdict"] = "reject" if before == "accept" else "accept"
    elif field_name == "recommended_action":
        before = payload.get("recommended_action", "")
        payload["recommended_action"] = (
            "isolate_device" if before == "close_as_false_positive" else "close_as_false_positive"
        )
    elif field_name == "severity_score":
        before = float(payload.get("severity_score", 0.0) or 0.0)
        # Move away from whichever end it is nearer, so the shift is always real and always visible.
        payload["severity_score"] = round(before - 0.4 if before >= 0.5 else before + 0.4, 4)
    else:
        raise ValueError(f"no tamper defined for agent {agent!r}")

    if payload[field_name] == before:
        raise ValueError(
            f"tamper of {agent}.{field_name} would not change the value ({before!r}); "
            "refusing to record a no-op that would display as untampered"
        )

    tampered_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    conn.execute(
        """INSERT INTO tamper_log (tamper_id, run_id, field, original_json, tampered_json, active)
           VALUES (?,?,?,?,?,1)""",
        (f"TMP-{run_id[-10:]}", run_id, field_name, original_json, tampered_json),
    )
    conn.execute(
        "UPDATE agent_runs SET output_json = ? WHERE run_id = ?", (tampered_json, run_id)
    )
    conn.commit()

    return {
        "run_id": run_id,
        "agent": agent,
        "field": field_name,
        "before": before,
        "after": payload[field_name],
    }


def restore(conn: sqlite3.Connection, workflow_id: str) -> int:
    """Undo every active tamper on this workflow, so the demo can be run again."""
    rows = conn.execute(
        """SELECT t.tamper_id, t.run_id, t.original_json
           FROM tamper_log t JOIN agent_runs r ON r.run_id = t.run_id
           WHERE r.workflow_id = ? AND t.active = 1""",
        (workflow_id,),
    ).fetchall()

    for tamper_id, run_id, original_json in rows:
        conn.execute(
            "UPDATE agent_runs SET output_json = ? WHERE run_id = ?", (original_json, run_id)
        )
        conn.execute("UPDATE tamper_log SET active = 0 WHERE tamper_id = ?", (tamper_id,))
    conn.commit()
    return len(rows)
