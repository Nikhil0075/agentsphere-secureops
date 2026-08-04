"""Edge confidence for the attack-path search.

Dijkstra needs a cost per edge, and that cost has to mean something. Here an edge's *confidence*
is how much we believe the two entities are genuinely related rather than incidentally
co-observed, on [0, 1]. Three components:

* **Detector strength** — the strongest suspicion level or verdict on the evidence rows that
  witnessed the edge. Two entities linked by a row the detector called Malicious is a stronger
  link than one it called Clean.
* **Entity rarity** — an edge involving entities seen across many incidents is weaker. Two
  incidents sharing a file hash means something; sharing ``powershell.exe`` means almost nothing.
* **Witness count** — an edge observed on several evidence rows beats one seen once.

**These weights are hand-set and sanity-checked, not learned.** §8.5 requires saying so plainly
rather than implying a fitted model, and the same honesty applies here: nothing in this file was
trained on anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import log2

import pandas as pd

from app.graph.build import EntityGraph, Node

#: Confidence floor. §8.2: clamp before taking -log so a zero-confidence edge cannot produce an
#: infinite cost and silently remove a path from consideration.
MIN_CONFIDENCE = 0.01

#: Component weights. Hand-set. They sum to 1.0 so the result stays on [0, 1].
WEIGHTS = {"detector": 0.50, "rarity": 0.35, "witnesses": 0.15}

_SUSPICION_STRENGTH = {
    "Malicious": 1.0,
    "Incriminated": 0.9,
    "Suspicious": 0.6,
    "Benign": 0.2,
    "Clean": 0.15,
    "NoThreatsFound": 0.1,
    "": 0.3,          # nothing recorded: mildly uncertain, not disbelieved
}


def _detector_strength(rows: pd.DataFrame) -> float:
    best = 0.0
    for column in ("suspicion_level", "last_verdict"):
        if column not in rows.columns:
            continue
        for value in rows[column].dropna().astype(str):
            best = max(best, _SUSPICION_STRENGTH.get(value.strip(), 0.3))
    return best or _SUSPICION_STRENGTH[""]


def _rarity(graph: EntityGraph, a: Node, b: Node) -> float:
    """Inverse of how widely the entities are spread across incidents.

    ``1 / log2(2 + span)`` — the same shape used by the entity-overlap retriever, for the same
    reason: it decays fast at first and then gently, which matches how quickly an entity stops
    being informative as it spreads.
    """
    span = max(graph.incident_span(a), graph.incident_span(b), 1)
    return min(1.0, 1.0 / log2(2 + span) * 1.5)


@dataclass
class ConfidenceModel:
    """Scores edges for one incident's subgraph."""

    graph: EntityGraph
    evidence: pd.DataFrame
    _by_alert: dict[str, pd.DataFrame] | None = None

    def __post_init__(self) -> None:
        if self._by_alert is None:
            self._by_alert = {
                str(alert_id): group
                for alert_id, group in self.evidence.groupby("alert_id", sort=False)
            }

    def _witnessing_rows(self, a: Node, b: Node) -> pd.DataFrame:
        """Evidence rows on alerts where both entities appear."""
        alerts = self.graph.node_alerts.get(a, set()) & self.graph.node_alerts.get(b, set())
        frames = [self._by_alert[alert] for alert in alerts if alert in self._by_alert]
        if not frames:
            return self.evidence.iloc[0:0]
        return pd.concat(frames) if len(frames) > 1 else frames[0]

    def confidence(self, a: Node, b: Node) -> float:
        rows = self._witnessing_rows(a, b)
        detector = _detector_strength(rows) if len(rows) else _SUSPICION_STRENGTH[""]
        rarity = _rarity(self.graph, a, b)
        witnesses = min(1.0, len(rows) / 5.0)

        score = (
            WEIGHTS["detector"] * detector
            + WEIGHTS["rarity"] * rarity
            + WEIGHTS["witnesses"] * witnesses
        )
        return max(MIN_CONFIDENCE, min(1.0, score))
