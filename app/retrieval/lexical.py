"""BM25 lexical retrieval over incident summaries.

BM25 rather than raw term overlap because it accounts for the three things that matter in this
corpus: term frequency, document length, and rare-term weight. A summary mentioning ``mimikatz``
once should outrank one mentioning ``powershell`` five times, and only the third of those factors
gets you there.

Elasticsearch/OpenSearch is not worth the operational cost at 5,000 documents (§8.1). `rank_bm25`
is a few hundred lines of pure Python and needs no server to be alive during a demo.
"""

from __future__ import annotations

import pickle
import re
from dataclasses import dataclass
from pathlib import Path

from rank_bm25 import BM25Okapi

#: Words that carry no discriminative signal in this corpus — every summary has them, so they
#: only add noise to the ranking. Deliberately short: aggressive stoplists throw away signal.
_STOPWORDS = frozenset(
    """
    a an and are as at be been by for from has have in is it its of on or that the to was were
    with incident alert alerts evidence item items detector category unknown unspecified none
    observed spanning minute minutes highest strongest level
    """.split()
)

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._:-]*")


def tokenize(text: str) -> list[str]:
    """Lowercase, split on non-word boundaries, drop stopwords and single characters.

    Dots, colons, underscores and hyphens are kept inside tokens on purpose: ``powershell.exe``,
    ``T1566.002`` and ``account:svc-backup`` are single meaningful terms, and splitting them
    would destroy exactly the identifiers that make two incidents comparable.
    """
    return [
        token
        for token in _TOKEN.findall(text.lower())
        if len(token) > 1 and token not in _STOPWORDS
    ]


@dataclass
class LexicalIndex:
    """BM25 over the incident summary corpus."""

    incident_ids: list[str]
    bm25: BM25Okapi

    @classmethod
    def build(cls, incident_ids: list[str], summaries: list[str]) -> "LexicalIndex":
        if len(incident_ids) != len(summaries):
            raise ValueError("incident_ids and summaries must be the same length")
        corpus = [tokenize(s) for s in summaries]
        # BM25Okapi divides by the average document length; an all-empty corpus would be a
        # zero divide deep inside the library rather than a clear error here.
        if not any(corpus):
            raise ValueError("every summary tokenised to nothing; check the summary builder")
        return cls(incident_ids=list(incident_ids), bm25=BM25Okapi(corpus))

    def __len__(self) -> int:
        return len(self.incident_ids)

    def search(self, query: str, k: int = 50, exclude: str | None = None) -> list[tuple[str, float]]:
        """Top-k ``(incident_id, score)``, best first.

        ``heapq.nlargest`` rather than a full sort: O(n log k) beats O(n log n) whenever k is
        small, which it always is here (§8.1).
        """
        import heapq

        tokens = tokenize(query)
        if not tokens:
            return []

        scores = self.bm25.get_scores(tokens)
        pairs = (
            (incident_id, float(score))
            for incident_id, score in zip(self.incident_ids, scores)
            if score > 0.0 and incident_id != exclude
        )
        # Tie-break on the id so the ranking is stable across runs and platforms.
        return heapq.nlargest(k, pairs, key=lambda kv: (kv[1], kv[0]))

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            pickle.dump({"incident_ids": self.incident_ids, "bm25": self.bm25}, fh)

    @classmethod
    def load(cls, path: str | Path) -> "LexicalIndex":
        with Path(path).open("rb") as fh:
            payload = pickle.load(fh)
        return cls(incident_ids=payload["incident_ids"], bm25=payload["bm25"])
