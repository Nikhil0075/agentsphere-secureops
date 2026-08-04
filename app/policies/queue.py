"""Risk-ordered incident queue (master plan §8.1).

``heapq`` is a min-heap, so risk is pushed negated. The tie-breaker matters more than it looks:
Python compares tuples element by element and falls through to the next element on a tie, so a
tuple ending in a non-comparable type raises ``TypeError`` the moment two incidents score
identically — which, with rounded risk scores, they will. Every element here is comparable
(float, float, str), and the trailing ``incident_id`` guarantees a total order, so ordering is
deterministic rather than merely usually-fine.

Complexity: push and pop O(log n), peek O(1), ``top_k`` O(n log k) via ``heapq.nlargest`` — which
is the point of using a heap at all rather than sorting the whole queue to look at five items.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator


@dataclass(order=False)
class QueueItem:
    incident_id: str
    risk: float
    severity: float = 0.0
    payload: dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple[float, float, str]:
        """Max-heap key: negate the descending fields, keep the id ascending as a tie-break."""
        return (-self.risk, -self.severity, self.incident_id)


class IncidentQueue:
    """A max-heap over incident risk."""

    def __init__(self, items: Iterable[QueueItem] | None = None) -> None:
        self._heap: list[tuple[tuple[float, float, str], QueueItem]] = []
        self._seen: set[str] = set()
        for item in items or ():
            self.push(item)

    def __len__(self) -> int:
        return len(self._heap)

    def __iter__(self) -> Iterator[QueueItem]:
        """Iterate in priority order without consuming the queue."""
        return iter(item for _, item in sorted(self._heap, key=lambda pair: pair[0]))

    def __contains__(self, incident_id: object) -> bool:
        return incident_id in self._seen

    def push(self, item: QueueItem) -> None:
        if item.incident_id in self._seen:
            raise ValueError(f"{item.incident_id} is already queued")
        self._seen.add(item.incident_id)
        heapq.heappush(self._heap, (item.sort_key(), item))

    def pop(self) -> QueueItem:
        if not self._heap:
            raise IndexError("pop from an empty queue")
        _, item = heapq.heappop(self._heap)
        self._seen.discard(item.incident_id)
        return item

    def peek(self) -> QueueItem:
        """Highest-risk incident, O(1)."""
        if not self._heap:
            raise IndexError("peek at an empty queue")
        return self._heap[0][1]

    def top_k(self, k: int) -> list[QueueItem]:
        """The k highest-risk incidents in O(n log k), without sorting the whole queue."""
        if k <= 0:
            return []
        smallest = heapq.nsmallest(k, self._heap, key=lambda pair: pair[0])
        return [item for _, item in smallest]

    def drain(self) -> list[QueueItem]:
        return [self.pop() for _ in range(len(self._heap))]


def from_frame(frame, risk_column: str = "risk_score") -> IncidentQueue:
    """Build a queue from an incident table."""
    items = []
    for row in frame.to_dict("records"):
        items.append(
            QueueItem(
                incident_id=str(row["incident_id"]),
                risk=float(row.get(risk_column, 0.0) or 0.0),
                severity=float(row.get("evidence_count", 0) or 0),
                payload=row,
            )
        )
    return IncidentQueue(items)
