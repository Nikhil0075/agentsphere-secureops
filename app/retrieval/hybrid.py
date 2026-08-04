"""Hybrid retrieval: BM25 + vectors, fused by Reciprocal Rank Fusion.

**One fusion method, not two.** §8.2 flags this precisely: a weighted linear formula over BM25
score, cosine similarity and metadata flags fuses *raw scores*; RRF fuses *rank positions*. They
are different mechanisms and presenting both invites a question with no clean answer. This module
uses RRF, and only RRF, to combine the two ranked lists.

Metadata is applied separately and afterwards, as a small multiplicative re-rank over the fused
top-k, for the reason §8.2 gives: a boost for "shares a MITRE technique" is not a ranked list, so
it cannot be folded into an RRF sum without inventing a rank for it.

    RRF(d) = Σ  1 / (k + rank_i(d))          k = 60, rank starting at 1
    final  = RRF(d) × Π (1 + boost_j)        over matching metadata facets

Why RRF at all: BM25 scores are unbounded and corpus-dependent, cosine is bounded on [-1, 1], and
normalising one against the other requires a scaling choice nobody can defend. Rank position
sidesteps that entirely — it is the reason RRF is the standard answer here.

**No label crosses this boundary.** See :mod:`app.retrieval.base`.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from app.retrieval.base import RetrievedIncident
from app.retrieval.lexical import LexicalIndex
from app.retrieval.vectors import VectorIndex

#: The standard RRF constant. Large enough that the difference between rank 1 and rank 2 does not
#: swamp everything below it; small enough that deep ranks still fade out.
RRF_K = 60

#: How many candidates each retriever contributes before fusion.
CANDIDATE_DEPTH = 50

#: Multiplicative boosts applied after fusion. Hand-set, and described as hand-set — they were
#: chosen to break ties between comparable candidates, not fitted to anything.
BOOSTS = {
    "mitre": 0.25,      # shares at least one ATT&CK technique
    "category": 0.10,   # same incident category
    "detector": 0.05,   # same detector produced it
}


def reciprocal_rank_fusion(
    ranked_lists: list[list[str]], k: int = RRF_K
) -> dict[str, float]:
    """Fuse ranked id lists into one score per id.

    Only rank position is used — the underlying scores are deliberately discarded, which is the
    whole point of RRF.
    """
    scores: dict[str, float] = defaultdict(float)
    for ranked in ranked_lists:
        for position, incident_id in enumerate(ranked, start=1):
            scores[incident_id] += 1.0 / (k + position)
    return dict(scores)


@dataclass
class IncidentFacets:
    """The metadata used for the post-fusion re-rank."""

    techniques: frozenset[str] = frozenset()
    category: str = ""
    detector: str = ""


def _facets_from(incidents: pd.DataFrame) -> dict[str, IncidentFacets]:
    facets: dict[str, IncidentFacets] = {}
    for row in incidents[
        ["incident_id", "mitre_techniques", "top_category", "top_detector"]
    ].to_dict("records"):
        raw = str(row.get("mitre_techniques") or "")
        techniques = frozenset(t.strip() for t in raw.replace(",", ";").split(";") if t.strip())
        facets[str(row["incident_id"])] = IncidentFacets(
            techniques=techniques,
            category=str(row.get("top_category") or ""),
            detector=str(row.get("top_detector") or ""),
        )
    return facets


@dataclass
class HybridRetriever:
    """BM25 + vector retrieval fused with RRF, then re-ranked on metadata.

    Implements the :class:`app.retrieval.base.Retriever` protocol, so the Investigation agent is
    unchanged from Day 3 — which is exactly what freezing that interface bought.
    """

    lexical: LexicalIndex
    vectors: VectorIndex
    summaries: dict[str, str]
    facets: dict[str, IncidentFacets] = field(default_factory=dict)
    rrf_k: int = RRF_K
    candidate_depth: int = CANDIDATE_DEPTH

    @classmethod
    def build(
        cls, incidents: pd.DataFrame, embedding_backend: str = "tfidf-svd"
    ) -> "HybridRetriever":
        incident_ids = [str(i) for i in incidents["incident_id"]]
        summaries = [str(s or "") for s in incidents["summary"]]
        return cls(
            lexical=LexicalIndex.build(incident_ids, summaries),
            vectors=VectorIndex.build(incident_ids, summaries, backend=embedding_backend),
            summaries=dict(zip(incident_ids, summaries)),
            facets=_facets_from(incidents),
        )

    # --- retrieval ----------------------------------------------------------------------

    def _boost(self, query_id: str, candidate_id: str) -> tuple[float, list[str]]:
        query = self.facets.get(query_id)
        candidate = self.facets.get(candidate_id)
        if query is None or candidate is None:
            return 1.0, []

        multiplier = 1.0
        why: list[str] = []
        shared = query.techniques & candidate.techniques
        if shared:
            multiplier *= 1.0 + BOOSTS["mitre"]
            why.append("MITRE " + ", ".join(sorted(shared)[:3]))
        if query.category and query.category == candidate.category:
            multiplier *= 1.0 + BOOSTS["category"]
            why.append(f"category {candidate.category}")
        if query.detector and query.detector == candidate.detector:
            multiplier *= 1.0 + BOOSTS["detector"]
            why.append(f"detector {candidate.detector}")
        return multiplier, why

    def similar(self, incident_id: str, k: int = 5) -> list[RetrievedIncident]:
        query_text = self.summaries.get(incident_id, "")

        lexical_hits = self.lexical.search(
            query_text, k=self.candidate_depth, exclude=incident_id
        )
        vector_hits = self.vectors.search(incident_id, k=self.candidate_depth)

        fused = reciprocal_rank_fusion(
            [[i for i, _ in lexical_hits], [i for i, _ in vector_hits]], k=self.rrf_k
        )
        if not fused:
            return []

        lexical_rank = {i: r for r, (i, _) in enumerate(lexical_hits, start=1)}
        vector_rank = {i: r for r, (i, _) in enumerate(vector_hits, start=1)}

        reranked: list[tuple[str, float, list[str]]] = []
        for candidate_id, score in fused.items():
            if candidate_id == incident_id:
                continue
            multiplier, why = self._boost(incident_id, candidate_id)
            if candidate_id in lexical_rank and candidate_id in vector_rank:
                why.append("both retrievers")
            elif candidate_id in lexical_rank:
                why.append("lexical match")
            else:
                why.append("semantic match")
            reranked.append((candidate_id, score * multiplier, why))

        # Tie-break on the id so identical scores rank identically on every run.
        reranked.sort(key=lambda item: (-item[1], item[0]))
        top = reranked[:k]
        if not top:
            return []

        ceiling = top[0][1] or 1.0
        return [
            RetrievedIncident(
                incident_id=candidate_id,
                score=round(min(1.0, score / ceiling), 4),
                summary=self.summaries.get(candidate_id, ""),
                shared_entities=tuple(why),
            )
            for candidate_id, score, why in top
        ]

    # --- persistence ---------------------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        import json

        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.lexical.save(directory / "bm25.pkl")
        self.vectors.save(directory)
        (directory / "corpus.json").write_text(
            json.dumps(
                {
                    "summaries": self.summaries,
                    "facets": {
                        i: {
                            "techniques": sorted(f.techniques),
                            "category": f.category,
                            "detector": f.detector,
                        }
                        for i, f in self.facets.items()
                    },
                    "rrf_k": self.rrf_k,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, directory: str | Path) -> "HybridRetriever":
        import json

        directory = Path(directory)
        corpus = json.loads((directory / "corpus.json").read_text(encoding="utf-8"))
        return cls(
            lexical=LexicalIndex.load(directory / "bm25.pkl"),
            vectors=VectorIndex.load(directory),
            summaries=corpus["summaries"],
            facets={
                i: IncidentFacets(
                    techniques=frozenset(f["techniques"]),
                    category=f["category"],
                    detector=f["detector"],
                )
                for i, f in corpus["facets"].items()
            },
            rrf_k=corpus.get("rrf_k", RRF_K),
        )


def load_if_available(directory: str | Path) -> HybridRetriever | None:
    """Load a prebuilt index, or return None so the caller can fall back."""
    directory = Path(directory)
    if (directory / "corpus.json").exists() and (directory / "bm25.pkl").exists():
        return HybridRetriever.load(directory)
    return None
