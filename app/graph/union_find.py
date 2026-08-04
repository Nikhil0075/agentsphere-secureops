"""Disjoint-set union with path compression **and** union by rank.

Both, not one. Path compression alone gives O(log n) amortised. The near-constant bound — formally
the inverse Ackermann function, O(α(n)) — requires compression together with union by rank or by
size (master plan §8.2, which corrects an earlier claim in v1). Stating the bound correctly is
part of the point, so the implementation has to earn it.

``find`` is iterative rather than recursive: a chain of a few hundred thousand evidence rows would
blow Python's recursion limit long before it blew anything else.
"""

from __future__ import annotations

from typing import Hashable, Iterable, Iterator, TypeVar

T = TypeVar("T", bound=Hashable)


class UnionFind:
    """Disjoint-set forest over arbitrary hashable elements."""

    def __init__(self, elements: Iterable[T] | None = None) -> None:
        self._parent: dict[T, T] = {}
        self._rank: dict[T, int] = {}
        self._count = 0
        for element in elements or ():
            self.add(element)

    def __len__(self) -> int:
        return len(self._parent)

    def __contains__(self, element: object) -> bool:
        return element in self._parent

    def __iter__(self) -> Iterator[T]:
        return iter(self._parent)

    @property
    def component_count(self) -> int:
        """Number of disjoint sets, maintained incrementally rather than recomputed."""
        return self._count

    def add(self, element: T) -> None:
        if element not in self._parent:
            self._parent[element] = element
            self._rank[element] = 0
            self._count += 1

    def find(self, element: T) -> T:
        """Representative of ``element``'s set, compressing the path on the way out."""
        if element not in self._parent:
            self.add(element)
            return element

        root = element
        while self._parent[root] != root:
            root = self._parent[root]

        # Second pass: point every node on the path straight at the root.
        while self._parent[element] != root:
            self._parent[element], element = root, self._parent[element]

        return root

    def union(self, a: T, b: T) -> bool:
        """Merge two sets. Returns True if they were previously separate."""
        root_a, root_b = self.find(a), self.find(b)
        if root_a == root_b:
            return False

        # Union by rank: hang the shorter tree off the taller one so depth grows slowly.
        rank_a, rank_b = self._rank[root_a], self._rank[root_b]
        if rank_a < rank_b:
            root_a, root_b = root_b, root_a
        self._parent[root_b] = root_a
        if rank_a == rank_b:
            self._rank[root_a] += 1

        self._count -= 1
        return True

    def connected(self, a: T, b: T) -> bool:
        return self.find(a) == self.find(b)

    def components(self) -> dict[T, list[T]]:
        """Every set, keyed by representative and sorted for deterministic output."""
        groups: dict[T, list[T]] = {}
        for element in self._parent:
            groups.setdefault(self.find(element), []).append(element)
        return {root: sorted(members, key=str) for root, members in sorted(groups.items(), key=lambda kv: str(kv[0]))}

    def component_sizes(self) -> list[int]:
        return sorted((len(m) for m in self.components().values()), reverse=True)
