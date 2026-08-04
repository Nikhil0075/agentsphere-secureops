"""Alert correlation via Union-Find (master plan §8.1).

Alerts that share a user, device, IP address, file hash or a time window are grouped into one
cluster. This is the visible half of the Day 3 exit criterion: scattered alerts collapsing into a
single incident cluster, on screen, from real data.

Two alerts are linked when either holds:

* they share at least one entity value of a linking type, or
* they are within ``time_window_minutes`` of each other **and** share an entity of any type.

The second rule is deliberately conjunctive. Time proximity alone would merge everything that
happened in the same hour, which in a SOC is everything.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

import pandas as pd

from app.data.schema import ENTITY_COLUMNS
from app.graph.union_find import UnionFind

#: Entity types strong enough to link two alerts on their own.
LINKING_TYPES = ("account", "device", "ip", "filehash")

DEFAULT_TIME_WINDOW_MINUTES = 60

#: An entity value shared by more alerts than this is treated as background, not as a link.
#: Sentinels are masked upstream, but a genuinely busy shared asset can still over-merge.
DEFAULT_MAX_SHARED_ALERTS = 200


@dataclass(frozen=True)
class Cluster:
    cluster_id: str
    alert_ids: list[str]
    linking_entities: list[str]
    evidence_count: int

    @property
    def size(self) -> int:
        return len(self.alert_ids)


@dataclass(frozen=True)
class CorrelationResult:
    clusters: list[Cluster]
    alert_count: int
    cluster_count: int
    largest_cluster: int
    reduction: float  # 1.0 - clusters/alerts; the "collapse" the demo shows

    def cluster_for(self, alert_id: str) -> Cluster | None:
        return next((c for c in self.clusters if alert_id in c.alert_ids), None)

    def as_dict(self) -> dict:
        return {
            "alerts": self.alert_count,
            "clusters": self.cluster_count,
            "largest_cluster": self.largest_cluster,
            "reduction": round(self.reduction, 4),
        }


def correlate(
    evidence: pd.DataFrame,
    time_window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES,
    linking_types: tuple[str, ...] = LINKING_TYPES,
    max_shared_alerts: int = DEFAULT_MAX_SHARED_ALERTS,
) -> CorrelationResult:
    """Group alerts into clusters. Deterministic: same input, same clusters, same ids."""
    alerts = sorted(str(a) for a in evidence["alert_id"].dropna().unique())
    uf = UnionFind(alerts)

    # entity value -> alerts that carry it
    by_entity: dict[tuple[str, str], set[str]] = defaultdict(set)
    # alert -> earliest timestamp, for the time-window rule
    alert_time: dict[str, pd.Timestamp] = {}

    timestamps = pd.to_datetime(
        evidence["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    work = evidence.assign(_ts=timestamps)

    for row in work.to_dict("records"):
        alert_id = str(row["alert_id"])
        ts = row["_ts"]
        if pd.notna(ts) and (alert_id not in alert_time or ts < alert_time[alert_id]):
            alert_time[alert_id] = ts
        for entity_type, column in ENTITY_COLUMNS.items():
            value = str(row.get(column, "") or "").strip()
            if value:
                by_entity[(entity_type, value)].add(alert_id)

    linking_entities: dict[str, set[str]] = defaultdict(set)

    for (entity_type, value), alert_set in by_entity.items():
        if len(alert_set) < 2 or len(alert_set) > max_shared_alerts:
            continue

        ordered = sorted(alert_set)
        strong = entity_type in linking_types

        for other in ordered[1:]:
            first = ordered[0]
            if strong or _within_window(
                alert_time.get(first), alert_time.get(other), time_window_minutes
            ):
                if uf.union(first, other):
                    label = f"{entity_type}:{value}"
                    linking_entities[first].add(label)
                    linking_entities[other].add(label)

    evidence_per_alert = evidence.groupby("alert_id").size().to_dict()

    grouped: dict[str, list[str]] = defaultdict(list)
    for alert_id in alerts:
        grouped[uf.find(alert_id)].append(alert_id)

    clusters = []
    for index, (root, members) in enumerate(sorted(grouped.items()), start=1):
        labels: set[str] = set()
        for member in members:
            labels |= linking_entities.get(member, set())
        clusters.append(
            Cluster(
                cluster_id=f"CL-{index:04d}",
                alert_ids=sorted(members),
                linking_entities=sorted(labels),
                evidence_count=sum(int(evidence_per_alert.get(m, 0)) for m in members),
            )
        )

    clusters.sort(key=lambda c: (-c.size, c.cluster_id))
    return CorrelationResult(
        clusters=clusters,
        alert_count=len(alerts),
        cluster_count=len(clusters),
        largest_cluster=max((c.size for c in clusters), default=0),
        reduction=(1.0 - len(clusters) / len(alerts)) if alerts else 0.0,
    )


def _within_window(a, b, minutes: int) -> bool:
    if a is None or b is None or pd.isna(a) or pd.isna(b):
        return False
    return abs(a - b) <= timedelta(minutes=minutes)
