"""Similar-incident retrieval interface.

Day 3 ships :class:`EntityOverlapRetriever` — a real, if blunt, retriever that scores candidates
by shared entity values. Day 4 replaces it with BM25 + FAISS fused by Reciprocal Rank Fusion
(k = 60) plus a metadata re-rank, behind this same interface, so the Investigation agent does not
change.

**No label ever crosses this boundary.** A retriever that returns the ground-truth label of a
similar incident would leak the answer into the prompt and make every metric meaningless. The
returned record carries the summary and the score, and nothing else.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol

import pandas as pd

from app.data.schema import ENTITY_COLUMNS

#: An entity value shared by more incidents than this is background, not evidence of similarity.
DEFAULT_MAX_INCIDENT_SPAN = 100


@dataclass(frozen=True)
class RetrievedIncident:
    incident_id: str
    score: float
    summary: str
    shared_entities: tuple[str, ...] = ()

    def why(self) -> str:
        if not self.shared_entities:
            return "textual similarity"
        return "shares " + ", ".join(self.shared_entities[:4])


class Retriever(Protocol):
    def similar(self, incident_id: str, k: int = 5) -> list[RetrievedIncident]: ...


class NullRetriever:
    """Returns nothing. Used when no corpus is available, so callers see an empty list rather
    than an exception."""

    def similar(self, incident_id: str, k: int = 5) -> list[RetrievedIncident]:
        return []


class EntityOverlapRetriever:
    """Score candidates by the entity values they share with the query incident.

    Rare entities count for more: sharing a file hash seen in two incidents is meaningful, sharing
    a process name seen in two thousand is not. The weight is ``1 / log2(2 + span)``, which is
    inverse-document-frequency in spirit without pretending to be a tuned formula.
    """

    def __init__(
        self,
        evidence: pd.DataFrame,
        incidents: pd.DataFrame,
        max_incident_span: int = DEFAULT_MAX_INCIDENT_SPAN,
    ) -> None:
        self.summaries: dict[str, str] = dict(
            zip(incidents["incident_id"], incidents.get("summary", ""))
        )
        self.max_incident_span = max_incident_span

        # entity value -> incidents carrying it, and the reverse
        self._entity_incidents: dict[tuple[str, str], set[str]] = defaultdict(set)
        self._incident_entities: dict[str, set[tuple[str, str]]] = defaultdict(set)

        columns = [c for c in ENTITY_COLUMNS.values() if c in evidence.columns]
        for row in evidence[["incident_id"] + columns].to_dict("records"):
            incident_id = str(row["incident_id"])
            for entity_type, column in ENTITY_COLUMNS.items():
                value = str(row.get(column, "") or "").strip()
                if value:
                    node = (entity_type, value)
                    self._entity_incidents[node].add(incident_id)
                    self._incident_entities[incident_id].add(node)

    def similar(self, incident_id: str, k: int = 5) -> list[RetrievedIncident]:
        from math import log2

        query = self._incident_entities.get(incident_id, set())
        if not query:
            return []

        scores: dict[str, float] = defaultdict(float)
        shared: dict[str, list[str]] = defaultdict(list)

        for node in query:
            carriers = self._entity_incidents.get(node, set())
            span = len(carriers)
            if span < 2 or span > self.max_incident_span:
                continue
            weight = 1.0 / log2(2 + span)
            for other in carriers:
                if other == incident_id:
                    continue
                scores[other] += weight
                shared[other].append(f"{node[0]}:{node[1]}")

        if not scores:
            return []

        top = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
        ceiling = top[0][1] or 1.0
        return [
            RetrievedIncident(
                incident_id=other,
                score=round(min(1.0, score / ceiling), 4),
                summary=self.summaries.get(other, ""),
                shared_entities=tuple(sorted(set(shared[other]))),
            )
            for other, score in top
        ]
