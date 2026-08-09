"""Human-readable incident summaries.

This text is the retrieval corpus on Day 4 (BM25 + embeddings) and the evidence block handed to
the agents on Day 3. It must be **pure and deterministic**: the same incident always produces the
same string, byte for byte. A summary that varies between runs changes the keccak256 hash of the
evidence bundle, which would break proof verification for reasons that have nothing to do with
tampering.

It must also contain no label. The label is ground truth; leaking it into the retrieval corpus or
an agent prompt would make every metric meaningless.
"""

from __future__ import annotations

import pandas as pd

from app.data.schema import ENTITY_COLUMNS

MAX_ENTITIES_PER_TYPE = 5
MAX_ALERT_TITLES = 4

_LEAKY_FIELDS = frozenset({"label", "label_int"})


def _text(value: object) -> str:
    """Render a dataset scalar without leaking pandas' missing-value sentinels.

    GUIDE is sparse. Converting a missing float to ``str`` produces the literal text ``nan``,
    which an LLM reasonably reads as an observed value rather than as absence. Keep absence
    absent in every prompt-facing summary.
    """
    if value is None:
        return ""
    try:
        if bool(pd.isna(value)):
            return ""
    except (TypeError, ValueError):
        pass
    rendered = str(value).strip()
    return "" if rendered.lower() in {"nan", "none", "<na>"} else rendered


def _opaque(value: str) -> bool:
    """True when a value is a bare surrogate id carrying no meaning to a reader.

    GUIDE anonymises most categorical text into integers: ``alert_title``, ``top_detector`` and
    ``top_category`` all arrive as numeric surrogates. Rendering those as though they were names
    produces lines like ``Distinct alert title (1): 1.`` and ``Detector: 1`` — which read as
    self-contradictions two lines under ``26 alert(s)``, and the Verifier said so, by name, on
    the flagship demo case. Naming them as ids is the difference between a confusing claim and
    an honest one.
    """
    return value.isdigit()


def _label_ids(values: list[str]) -> str:
    """Render values, marking them as ids when that is all they are."""
    joined = "; ".join(values)
    return f"{joined} (opaque numeric id(s), not names)" if all(map(_opaque, values)) else joined


def _distinct(series: pd.Series, limit: int) -> list[str]:
    seen: list[str] = []
    for raw in series:
        value = _text(raw)
        if value and value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return sorted(seen)


def build_incident_summary(incident: dict | pd.Series, evidence: pd.DataFrame) -> str:
    """Render one incident as plain text. Deterministic; contains no ground-truth label."""
    if isinstance(incident, pd.Series):
        incident = incident.to_dict()
    incident = {k: v for k, v in incident.items() if k not in _LEAKY_FIELDS}

    lines: list[str] = []
    lines.append(f"Incident {incident.get('incident_id', '')}")
    detector = str(incident.get("top_detector") or "unknown")
    lines.append(
        f"Category: {incident.get('top_category') or 'unknown'}. "
        f"Detector: {detector}"
        + (" (opaque numeric id, not a name)." if _opaque(detector) else ".")
    )
    lines.append(
        f"{incident.get('alert_count', 0)} alert(s), "
        f"{incident.get('evidence_count', 0)} evidence item(s), "
        f"spanning {float(incident.get('duration_minutes', 0) or 0):.0f} minute(s) "
        f"from {incident.get('first_seen') or 'unknown'}."
    )

    titles = _distinct(evidence["alert_title"], MAX_ALERT_TITLES)
    if titles:
        # Two separate hazards here, and only the first was fixed before. Naming the field
        # "Distinct alert titles" rather than "Alerts" stops it reading as an alert *count* that
        # contradicts the line above. But GUIDE anonymises the title itself into an integer, so
        # the line still rendered as "Distinct alert title (1): 1." — a label of 1 with a value
        # of 1, which the Verifier quoted back as "Alerts: 1" and escalated on. Say what the
        # value actually is.
        plural = "title" if len(titles) == 1 else "titles"
        lines.append(f"Distinct alert {plural} ({len(titles)}): {_label_ids(titles)}.")

    highest = incident.get("max_suspicion_level") or "unspecified"
    verdict = incident.get("max_last_verdict") or "unspecified"
    lines.append(f"Highest suspicion level: {highest}. Strongest verdict: {verdict}.")

    families = incident.get("threat_families") or ""
    if families:
        lines.append("Threat families observed: " + families.replace(";", ", ") + ".")

    techniques = incident.get("mitre_techniques") or ""
    if techniques:
        lines.append("MITRE ATT&CK techniques: " + techniques.replace(";", ", ") + ".")

    entity_lines: list[str] = []
    for entity_type, column in ENTITY_COLUMNS.items():
        if column not in evidence.columns:
            continue
        values = _distinct(evidence[column], MAX_ENTITIES_PER_TYPE)
        if values:
            entity_lines.append(f"{entity_type}: {', '.join(values)}")
    if entity_lines:
        lines.append("Entities — " + "; ".join(sorted(entity_lines)) + ".")

    return "\n".join(lines)


def build_evidence_block(evidence: pd.DataFrame, limit: int = 25) -> str:
    """Compact, referencable evidence listing for agent prompts.

    Every line is prefixed with its evidence id so an agent can cite it and the Verifier can
    check the citation later (§6.1 requires ``supporting_evidence_ids``).
    """
    rows = []
    for _, row in evidence.head(limit).iterrows():
        evidence_id = _text(row.get("evidence_id"))
        alert_id = _text(row.get("alert_id"))
        parts = [f"[{evidence_id}]", f"alert={alert_id}"]
        for key in (
            "entity_type",
            "evidence_role",
            "suspicion_level",
            "last_verdict",
            "account_upn",
            "device_id",
            "ip_address",
            "file_name",
            "file_sha256",
            "url",
        ):
            value = _text(row.get(key, ""))
            if value:
                if key == "file_sha256":
                    value = value[:16] + "…"
                parts.append(f"{key}={value}")
        rows.append(" ".join(parts))
    if len(evidence) > limit:
        rows.append(f"... {len(evidence) - limit} further evidence item(s) omitted")
    return "\n".join(rows)
