"""Persist a completed workflow, its approvals and its on-chain proof.

The split this module enforces (§4.3): **raw evidence and agent outputs live in SQLite; only
digests, identities and approval state go on chain.** The chain client is never handed anything
but hashes — not because callers are trusted to be careful, but because this is the only place
that talks to both, and there is nothing here that passes evidence content across.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass

from app.agents.schemas import WorkflowState
from app.blockchain.client import AnchorResult, ChainClient
from app.blockchain.hashing import hash_payload
from app.observability.logging import log_event
from app.orchestration.workflow import WorkflowResult


@dataclass
class PersistedDecision:
    decision_id: str
    incident_id: str
    workflow_id: str
    requires_approval: bool
    action_risk: str


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def save_decision(conn: sqlite3.Connection, result: WorkflowResult) -> PersistedDecision:
    """Write the workflow's conclusion into ``decisions``."""
    state: WorkflowState = result.state
    decision_id = _new_id("DEC")
    action_risk = (
        result.gate.action_risk
        if result.gate
        else (state.remediation.action_risk.value if state.remediation else "high")
    )

    conn.execute(
        """
        INSERT INTO decisions (
            decision_id, workflow_id, incident_id, label, confidence,
            baseline_label, baseline_confidence, recommended_action, action_risk,
            requires_approval, verifier_verdict, state, evidence_hash, output_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            decision_id,
            state.workflow_id,
            state.incident_id,
            state.triage.label.value if state.triage else None,
            state.triage.confidence if state.triage else None,
            state.baseline.label.value if state.baseline else None,
            state.baseline.confidence if state.baseline else None,
            state.remediation.recommended_action if state.remediation else None,
            action_risk,
            int(state.requires_approval),
            state.verifier.verdict.value if state.verifier else None,
            "proposed",
            state.evidence_hash,
            state.output_hash,
        ),
    )
    conn.commit()

    return PersistedDecision(
        decision_id=decision_id,
        incident_id=state.incident_id,
        workflow_id=state.workflow_id,
        requires_approval=state.requires_approval,
        action_risk=action_risk,
    )


def record_approval(
    conn: sqlite3.Connection,
    decision_id: str,
    approver: str,
    approved: bool,
    comment: str = "",
    signature: str = "",
) -> str:
    """Record a human decision. The comment stays here; only its hash can go on chain."""
    approval_id = _new_id("APR")
    comment_hash = hash_payload({"comment": comment, "approver": approver})

    conn.execute(
        """
        INSERT INTO approvals (approval_id, decision_id, approver, approved, comment,
                               comment_hash, signature)
        VALUES (?,?,?,?,?,?,?)
        """,
        (approval_id, decision_id, approver, int(approved), comment, comment_hash, signature),
    )
    conn.execute(
        "UPDATE decisions SET state = ? WHERE decision_id = ?",
        ("approved" if approved else "rejected", decision_id),
    )
    conn.commit()

    log_event(
        "approval_recorded",
        decision_id=decision_id,
        approver=approver,
        approved=approved,
        comment_hash=comment_hash,
    )
    return approval_id


def comment_hash_for(decision_id: str, conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT comment_hash FROM approvals WHERE decision_id = ? ORDER BY created_at DESC LIMIT 1",
        (decision_id,),
    ).fetchone()
    return (row[0] if row else "") or hash_payload({"comment": "", "approver": ""})


def advance_onchain_decision(
    client: ChainClient,
    onchain_decision_id: int,
    risk: str,
    *,
    approved: bool | None = None,
    comment_hash: str = "",
    initial_state: str = "",
) -> tuple[str, str]:
    """Advance the contract lifecycle after submission, idempotently.

    Approval and anchoring are separate UI actions and can happen in either order. The old API
    mirrored an approval only when approval happened *after* anchoring; approve-first/anchor-second
    left the contract permanently Proposed. Low-risk decisions were never finalized either. This
    reconciles both orderings while retaining the contract's human gate for medium/high risk.

    Returns ``(state, reason)``. A non-empty reason means the proof is anchored but a later
    lifecycle transaction could not be completed.
    """

    def observed(default: str) -> str:
        record = client.get_decision(onchain_decision_id) or {}
        state = str(record.get("state", "") or "").lower()
        return "proposed" if state == "submitted" else (state or default)

    state = (initial_state or "").lower()
    state = "proposed" if state in {"", "submitted"} else state
    if state in {"finalized", "rejected"}:
        return state, ""

    if state == "proposed" and approved is not None:
        approval = client.approve_decision(
            onchain_decision_id,
            approved,
            comment_hash or hash_payload({"comment": "", "approver": ""}),
        )
        if not approval.anchored:
            current = observed(state)
            if current == state:
                return state, f"approval sync failed: {approval.reason}"
            state = current
        else:
            state = "approved" if approved else "rejected"

    if state == "rejected":
        return state, ""

    should_finalize = state == "approved" or (
        state == "proposed" and risk.lower() == "low" and approved is None
    )
    if should_finalize:
        final = client.finalize_decision(onchain_decision_id)
        if final.anchored:
            return "finalized", ""
        current = observed(state)
        if current == "finalized":
            return current, ""
        return current, f"finalization failed: {final.reason}"

    return state, ""


def update_onchain_state(
    conn: sqlite3.Connection, decision_id: str, onchain_decision_id: int, state: str
) -> None:
    """Persist a witnessed contract state for zero-RPC Proof reloads."""
    conn.execute(
        """UPDATE blockchain_proofs SET onchain_state = ?, onchain_decision_id = ?
           WHERE proof_id = (
               SELECT proof_id FROM blockchain_proofs
               WHERE decision_id = ?
                 AND (COALESCE(tx_hash, '') != '' OR onchain_decision_id IS NOT NULL)
               ORDER BY created_at DESC, rowid DESC LIMIT 1
           )""",
        (state, onchain_decision_id, decision_id),
    )
    conn.commit()


def anchor_decision(
    conn: sqlite3.Connection,
    decision_id: str,
    result: WorkflowResult,
    client: ChainClient,
) -> AnchorResult:
    """Submit the decision's digests on chain and record the proof.

    Only four things cross the boundary: the incident id, two hashes, and a label and risk level.
    No evidence, no prompt, no rationale.
    """
    state = result.state
    action_risk = (
        result.gate.action_risk
        if result.gate
        else (state.remediation.action_risk.value if state.remediation else "high")
    )

    anchor = client.submit_decision(
        incident_id=state.incident_id,
        evidence_hash=state.evidence_hash,
        output_hash=state.output_hash,
        label=state.triage.label.value if state.triage else "Unknown",
        risk=action_risk,
    )

    conn.execute(
        """
        INSERT INTO blockchain_proofs (
            proof_id, decision_id, chain_id, contract_address, tx_hash, block_number,
            gas_used, agent_address, evidence_hash, output_hash, onchain_decision_id,
            onchain_state, failure_reason, anchored_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
        """,
        (
            _new_id("PRF"),
            decision_id,
            anchor.chain_id,
            anchor.contract_address,
            anchor.tx_hash,
            anchor.block_number,
            # Both write paths must record the same facts. This one predates `gas_used` and
            # `failure_reason`, so a CLI anchor -- which is what a rehearsal uses -- produced a row
            # the Proof screen then rendered with an empty gas figure and no reason for a failure.
            anchor.gas_used,
            anchor.agent_address,
            state.evidence_hash,
            state.output_hash,
            anchor.decision_id,
            (anchor.onchain_state or "proposed") if anchor.anchored else "unanchored",
            "" if anchor.anchored else (anchor.reason or ""),
        ),
    )
    conn.commit()

    log_event(
        "decision_anchored",
        decision_id=decision_id,
        incident_id=state.incident_id,
        anchored=anchor.anchored,
        tx_hash=anchor.tx_hash,
        onchain_decision_id=anchor.decision_id,
        reason=anchor.reason,
    )
    return anchor


def verify_decision(
    conn: sqlite3.Connection, decision_id: str, client: ChainClient | None = None
) -> dict:
    """Recompute-and-compare against what was anchored.

    ``valid`` false with a chain available is the tamper signal: the stored record no longer
    hashes to what the chain recorded.

    ``client`` may be ``None``, which means "answer from stored data alone and make no network
    call". The caller gets `valid=None` and `chain_available=False`, which is exactly the state a
    display route wants: everything known locally, and an honest "we did not ask" rather than a
    fabricated verdict. Connecting to a chain is expensive enough that it must be a decision the
    caller makes, not a side effect of rendering a page.
    """
    row = conn.execute(
        """
        SELECT d.evidence_hash, d.output_hash, p.tx_hash, p.chain_id, p.contract_address,
               p.onchain_decision_id
        FROM decisions d
        LEFT JOIN blockchain_proofs p ON p.decision_id = d.decision_id
        WHERE d.decision_id = ?
        ORDER BY
            CASE WHEN COALESCE(p.tx_hash, '') != '' OR p.onchain_decision_id IS NOT NULL
                 THEN 0 ELSE 1 END,
            p.created_at DESC, p.rowid DESC
        LIMIT 1
        """,
        (decision_id,),
    ).fetchone()
    if row is None:
        return {"decision_id": decision_id, "found": False}

    evidence_hash, output_hash, tx_hash, chain_id, contract, stored_onchain_id = row
    available = bool(client is not None and client.available)
    onchain_id = int(stored_onchain_id) if stored_onchain_id else None
    if available:
        onchain_id = onchain_id or client.find_by_fingerprint(
            conn.execute(
                "SELECT incident_id FROM decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()[0],
            evidence_hash,
            output_hash,
        )

    valid = (
        client.verify(int(onchain_id), evidence_hash, output_hash)
        if onchain_id and client is not None
        else None
    )

    return {
        "decision_id": decision_id,
        "found": True,
        "evidence_hash": evidence_hash,
        "output_hash": output_hash,
        "tx_hash": tx_hash,
        "chain_id": chain_id,
        "contract_address": contract,
        "onchain_decision_id": onchain_id,
        "valid": valid,
        "chain_available": available,
    }
