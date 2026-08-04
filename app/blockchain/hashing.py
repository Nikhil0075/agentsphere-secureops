"""Canonical JSON and keccak256 (master plan §8.2).

Landed on Day 3 rather than Day 5 for one reason: agent outputs have to be hash-stable from the
moment they are first written. Contracts and anchoring can wait; a hash function that changes
after outputs exist cannot.

**keccak256, not SHA-256.** Both work for anchoring a digest, but keccak256 is Solidity's native
hash, is cheaper to recompute on-chain, and is required if any Merkle inclusion proof is ever
verified inside the contract. Using it consistently from the start removes a migration.

**Canonicalisation is the whole game.** Sorted keys, no whitespace, deterministic separators,
NaN and Infinity rejected. Hash stability depends entirely on this and on nothing else, so the
rules are enforced here rather than trusted to callers.

**No Merkle tree.** §8.2 is explicit that shipping no Merkle tree is safer than shipping a broken
one, and a plain bundle hash is sufficient for the MVP. If one is added later it must
domain-separate leaf and internal hashing with distinct prefix bytes and handle an odd node count
explicitly rather than duplicating the last leaf.
"""

from __future__ import annotations

import json
import math
from typing import Any, Iterable

from eth_hash.auto import keccak

#: Prefix reserved for a future Merkle implementation. Unused today, documented so that if leaves
#: are ever hashed they are domain-separated from internal nodes rather than interchangeable.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class CanonicalisationError(ValueError):
    pass


def _check_floats(value: Any) -> None:
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalisationError(
                "NaN and Infinity have no canonical JSON representation; "
                "a hash over them would not be reproducible"
            )
    elif isinstance(value, dict):
        for v in value.values():
            _check_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check_floats(v)


def canonical_json(payload: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, no ASCII escaping surprises."""
    _check_floats(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    )


def keccak256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "0x" + keccak(data).hex()


def hash_payload(payload: Any) -> str:
    """keccak256 over the canonical JSON rendering of ``payload``."""
    return keccak256(canonical_json(payload))


def hash_evidence_bundle(evidence_ids: Iterable[str], incident_id: str = "") -> str:
    """Hash of the evidence an agent actually consumed.

    Ids are sorted and de-duplicated, so the same evidence set produces the same hash regardless
    of the order it was assembled in.
    """
    return hash_payload(
        {"incident_id": incident_id, "evidence_ids": sorted(set(evidence_ids))}
    )


def hash_agent_output(agent: str, output: Any) -> str:
    """Hash of one agent's output, bound to which agent produced it.

    Including the agent name means an identical payload attributed to a different agent is a
    different hash — the proof records who decided, not only what was decided.
    """
    payload = output.model_dump(mode="json") if hasattr(output, "model_dump") else output
    return hash_payload({"agent": agent, "output": payload})


def hash_decision(
    incident_id: str,
    evidence_hash: str,
    outputs: dict[str, Any],
    label: str = "",
    action: str = "",
) -> str:
    """The single digest anchored on-chain on Day 5.

    Deliberately excludes prompts, raw evidence and any personal data — the contract stores this
    hash, and the application database stores what it attests to (§4.3, §10.2).
    """
    return hash_payload(
        {
            "incident_id": incident_id,
            "evidence_hash": evidence_hash,
            "label": label,
            "action": action,
            "outputs": {
                name: (o.model_dump(mode="json") if hasattr(o, "model_dump") else o)
                for name, o in sorted(outputs.items())
            },
        }
    )


def verify(payload: Any, expected_hash: str) -> bool:
    """Recompute and compare. This is the UI's Valid / Tampered check on Day 6."""
    return hash_payload(payload) == expected_hash
