"""Everything an agent may look at for one incident, assembled once.

Agents receive this rather than a database handle. Two reasons: the deterministic backend and the
LLM backend then reason over identical facts, and the set of things an agent *can* see is a small
readable dataclass instead of whatever it manages to query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from app.data.schema import ENTITY_COLUMNS
from app.graph.correlate import CorrelationResult
from app.retrieval.base import RetrievedIncident

#: Ground truth must never reach an agent. Enforced in :meth:`IncidentContext.from_incident`.
FORBIDDEN_FIELDS = frozenset({"label", "label_int"})


@dataclass
class IncidentContext:
    incident_id: str
    summary: str
    evidence: pd.DataFrame
    incident_fields: dict[str, Any] = field(default_factory=dict)
    correlation: CorrelationResult | None = None
    similar: list[RetrievedIncident] = field(default_factory=list)
    baseline: dict[str, Any] | None = None

    @classmethod
    def from_incident(
        cls,
        incident: dict | pd.Series,
        evidence: pd.DataFrame,
        correlation: CorrelationResult | None = None,
        similar: list[RetrievedIncident] | None = None,
        baseline: dict[str, Any] | None = None,
    ) -> "IncidentContext":
        if isinstance(incident, pd.Series):
            incident = incident.to_dict()
        safe = {k: v for k, v in incident.items() if k not in FORBIDDEN_FIELDS}
        return cls(
            incident_id=str(safe.get("incident_id", "")),
            summary=str(safe.get("summary", "")),
            evidence=evidence,
            incident_fields=safe,
            correlation=correlation,
            similar=similar or [],
            baseline=baseline,
        )

    # --- derived views ------------------------------------------------------------------

    @property
    def evidence_ids(self) -> list[str]:
        return [str(e) for e in self.evidence["evidence_id"].tolist()]

    def evidence_payloads(self, evidence_ids: list[str] | None = None) -> dict[str, str]:
        """Canonical payload string per evidence id, for the evidence content digest.

        Uses the same serialiser the database writer uses, so the digest computed here at
        workflow time and the one recomputed later from stored rows are byte-identical by
        construction rather than by coincidence.
        """
        from app.db.session import canonical_evidence_payload

        if self.evidence is None or not len(self.evidence):
            return {}
        wanted = set(evidence_ids) if evidence_ids is not None else None
        payloads: dict[str, str] = {}
        for row in self.evidence.to_dict("records"):
            eid = str(row.get("evidence_id", ""))
            if wanted is None or eid in wanted:
                payloads[eid] = canonical_evidence_payload(row)
        return payloads

    def entity_counts(self) -> dict[str, int]:
        out = {}
        for entity_type, column in ENTITY_COLUMNS.items():
            if column not in self.evidence.columns:
                continue
            values = self.evidence[column].astype(str).str.strip()
            count = int(values[values != ""].nunique())
            if count:
                out[entity_type] = count
        return out

    def top_entities(self, limit: int = 8) -> list[tuple[str, str, int]]:
        """``(entity_type, value, evidence_rows)`` for the most frequently observed entities."""
        rows: list[tuple[str, str, int]] = []
        for entity_type, column in ENTITY_COLUMNS.items():
            if column not in self.evidence.columns:
                continue
            values = self.evidence[column].astype(str).str.strip()
            values = values[values != ""]
            for value, count in values.value_counts().head(limit).items():
                rows.append((entity_type, str(value), int(count)))
        return sorted(rows, key=lambda r: (-r[2], r[0], r[1]))[:limit]

    def all_entity_values(self) -> set[str]:
        """Every entity value observed anywhere in this incident's evidence.

        This is the grounding allowlist, and it is deliberately wider than ``top_entities``. The
        prompt shows the model an evidence block as well as the top-N summary, so an entity can be
        genuinely present in the incident and absent from the top N. Validating against the
        narrower list rejected real citations as hallucinations -- it failed three of the six demo
        cases before this existed.
        """
        out: set[str] = set()
        for column in ENTITY_COLUMNS.values():
            if column not in self.evidence.columns:
                continue
            values = self.evidence[column].astype(str).str.strip()
            out.update(values[values != ""].unique())
        return out

    def mitre_techniques(self) -> list[str]:
        out: set[str] = set()
        for raw in self.evidence.get("mitre_techniques", pd.Series(dtype=str)).dropna():
            for token in str(raw).replace(",", ";").split(";"):
                token = token.strip()
                if token:
                    out.add(token)
        return sorted(out)

    def suspicion_profile(self) -> dict[str, int]:
        profile: dict[str, int] = {}
        for column in ("suspicion_level", "last_verdict"):
            if column not in self.evidence.columns:
                continue
            values = self.evidence[column].astype(str).str.strip()
            for value, count in values[values != ""].value_counts().items():
                profile[f"{column}:{value}"] = int(count)
        return profile

    def timeline_rows(self, limit: int = 20) -> list[dict[str, str]]:
        if "timestamp" not in self.evidence.columns:
            return []
        frame = self.evidence[["evidence_id", "timestamp", "alert_title", "entity_type"]].copy()
        frame["_ts"] = pd.to_datetime(
            frame["timestamp"], errors="coerce", utc=True, format="mixed"
        )
        frame = frame.dropna(subset=["_ts"]).sort_values("_ts").head(limit)
        return [
            {
                "evidence_id": str(row["evidence_id"]),
                "timestamp": row["_ts"].isoformat(),
                "description": f"{row['entity_type']} observed — {row['alert_title']}",
            }
            for _, row in frame.iterrows()
        ]

    def baseline_tp_probability(self) -> float:
        if not self.baseline:
            return 0.5
        return float(self.baseline.get("probabilities", {}).get("TruePositive", 0.5))
