"""Stable identifiers.

Assigned once, before anything is hashed. Day 5 anchors evidence and output hashes on-chain and
those proofs reference these ids, so an id that shifts between runs silently invalidates every
proof ever written. They are therefore derived from content, not from row order or a counter.
"""

from __future__ import annotations

import hashlib

_INCIDENT_PREFIX = "INC"
_EVIDENCE_PREFIX = "EVD"
_ALERT_PREFIX = "ALT"


def _digest(*parts: object, length: int = 12) -> str:
    joined = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:length]


def incident_id(org_id: object, incident_ref: object) -> str:
    """Stable id for an incident. GUIDE's ``IncidentId`` is only unique within an org."""
    return f"{_INCIDENT_PREFIX}-{_digest(org_id, incident_ref)}"


def alert_id(org_id: object, incident_ref: object, alert_ref: object) -> str:
    return f"{_ALERT_PREFIX}-{_digest(org_id, incident_ref, alert_ref)}"


def evidence_id(org_id: object, incident_ref: object, alert_ref: object, row_ref: object) -> str:
    return f"{_EVIDENCE_PREFIX}-{_digest(org_id, incident_ref, alert_ref, row_ref)}"


def split_bucket(incident_id_value: str) -> int:
    """Deterministic 0-99 bucket used for train/val/demo assignment.

    Keyed on the incident id, so every row of an incident lands in the same split — the leakage
    path that actually matters when rows are evidence-level.
    """
    digest = hashlib.sha256(incident_id_value.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100
