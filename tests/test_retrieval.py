"""Hybrid retrieval: BM25, vectors, RRF fusion and the metadata re-rank.

The leakage tests matter most. Retrieval is the one place a ground-truth label could plausibly
reach an agent prompt by accident, and if it ever does, every metric this project reports becomes
meaningless.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.data import fixture
from app.data import incidents as incidents_mod
from app.data.summarize import build_incident_summary
from app.retrieval.hybrid import (
    BOOSTS,
    RRF_K,
    HybridRetriever,
    IncidentFacets,
    reciprocal_rank_fusion,
)
from app.retrieval.lexical import LexicalIndex, tokenize
from app.retrieval.vectors import VectorIndex, l2_normalise


@pytest.fixture(scope="module")
def corpus():
    evidence = fixture.generate(n_incidents=60)
    incidents = incidents_mod.aggregate(evidence)
    summaries = []
    for _, row in incidents.iterrows():
        rows = incidents_mod.evidence_for(evidence, row["incident_id"])
        summaries.append(build_incident_summary(row, rows))
    incidents["summary"] = summaries
    return evidence, incidents


@pytest.fixture(scope="module")
def retriever(corpus):
    _, incidents = corpus
    return HybridRetriever.build(incidents, embedding_backend="tfidf-svd")


# --- tokenisation ------------------------------------------------------------------------

def test_identifiers_survive_tokenisation():
    """powershell.exe and T1566.002 are single terms; splitting them destroys the signal."""
    tokens = tokenize("Suspicious powershell.exe and technique T1566.002 on account:svc-backup")
    assert "powershell.exe" in tokens
    assert "t1566.002" in tokens
    assert "account:svc-backup" in tokens


def test_stopwords_and_single_characters_are_dropped():
    tokens = tokenize("the incident is a and of x")
    assert tokens == []


# --- BM25 --------------------------------------------------------------------------------

def test_bm25_ranks_an_exact_match_first(corpus):
    _, incidents = corpus
    index = LexicalIndex.build(
        list(incidents["incident_id"]), list(incidents["summary"])
    )
    target = incidents.iloc[3]
    hits = index.search(target["summary"], k=5)
    assert hits[0][0] == target["incident_id"]


def test_bm25_excludes_the_query_incident(corpus):
    _, incidents = corpus
    index = LexicalIndex.build(list(incidents["incident_id"]), list(incidents["summary"]))
    target = incidents.iloc[3]
    hits = index.search(target["summary"], k=5, exclude=target["incident_id"])
    assert all(i != target["incident_id"] for i, _ in hits)


def test_bm25_returns_nothing_for_an_unmatchable_query(corpus):
    _, incidents = corpus
    index = LexicalIndex.build(list(incidents["incident_id"]), list(incidents["summary"]))
    assert index.search("the and of a", k=5) == []


def test_bm25_survives_a_save_load_round_trip(corpus, tmp_path):
    _, incidents = corpus
    index = LexicalIndex.build(list(incidents["incident_id"]), list(incidents["summary"]))
    index.save(tmp_path / "bm25.pkl")
    reloaded = LexicalIndex.load(tmp_path / "bm25.pkl")
    query = incidents["summary"].iloc[0]
    assert index.search(query, k=5) == reloaded.search(query, k=5)


def test_an_empty_corpus_fails_loudly(corpus):
    with pytest.raises(ValueError):
        LexicalIndex.build(["INC-1"], ["the and of"])


# --- vectors -----------------------------------------------------------------------------

def test_normalised_vectors_are_unit_length():
    vectors = l2_normalise(np.array([[3.0, 4.0], [1.0, 0.0]], dtype=np.float32))
    assert np.allclose(np.linalg.norm(vectors, axis=1), 1.0)


def test_a_zero_vector_does_not_divide_by_zero():
    vectors = l2_normalise(np.array([[0.0, 0.0]], dtype=np.float32))
    assert not np.isnan(vectors).any()


def test_inner_product_of_normalised_vectors_is_cosine():
    """This is the §8.1 requirement: normalise, then inner product."""
    a = l2_normalise(np.array([[1.0, 1.0]], dtype=np.float32))
    b = l2_normalise(np.array([[1.0, 0.0]], dtype=np.float32))
    assert np.isclose((a @ b.T).item(), np.cos(np.pi / 4), atol=1e-6)


def test_vector_search_finds_the_nearest_neighbour(corpus):
    _, incidents = corpus
    index = VectorIndex.build(
        list(incidents["incident_id"]), list(incidents["summary"]), backend="tfidf-svd"
    )
    target = str(incidents["incident_id"].iloc[0])
    hits = index.search(target, k=5)
    assert hits
    assert all(i != target for i, _ in hits), "the query must never be its own neighbour"


def test_the_query_vector_is_a_lookup_not_a_computation(corpus):
    """This is what keeps retrieval working with no network at demo time."""
    _, incidents = corpus
    index = VectorIndex.build(
        list(incidents["incident_id"]), list(incidents["summary"]), backend="tfidf-svd"
    )
    assert index.vector_for(str(incidents["incident_id"].iloc[0])) is not None
    assert index.vector_for("INC-does-not-exist") is None


def test_vectors_survive_a_save_load_round_trip(corpus, tmp_path):
    _, incidents = corpus
    index = VectorIndex.build(
        list(incidents["incident_id"]), list(incidents["summary"]), backend="tfidf-svd"
    )
    index.save(tmp_path)
    reloaded = VectorIndex.load(tmp_path)
    assert np.allclose(index.vectors, reloaded.vectors)
    target = str(incidents["incident_id"].iloc[0])
    assert index.search(target, k=3) == reloaded.search(target, k=3)


# --- RRF ---------------------------------------------------------------------------------

def test_rrf_uses_rank_position_only():
    """The whole point: raw scores are discarded, so BM25 and cosine never need normalising."""
    scores = reciprocal_rank_fusion([["a", "b"], ["b", "a"]])
    assert scores["a"] == scores["b"]


def test_rrf_rewards_appearing_in_both_lists():
    scores = reciprocal_rank_fusion([["a", "x"], ["a", "y"]])
    assert scores["a"] > scores["x"]
    assert scores["a"] > scores["y"]


def test_rrf_first_place_beats_second():
    scores = reciprocal_rank_fusion([["a", "b"]])
    assert scores["a"] > scores["b"]


def test_rrf_matches_the_formula():
    scores = reciprocal_rank_fusion([["a"]], k=60)
    assert scores["a"] == pytest.approx(1 / 61)


def test_rrf_k_is_sixty():
    assert RRF_K == 60


def test_rrf_of_nothing_is_empty():
    assert reciprocal_rank_fusion([]) == {}
    assert reciprocal_rank_fusion([[], []]) == {}


# --- fusion and re-rank ------------------------------------------------------------------

def test_hybrid_returns_results(retriever, corpus):
    _, incidents = corpus
    hits = retriever.similar(str(incidents["incident_id"].iloc[0]), k=5)
    assert hits
    assert len(hits) <= 5


def test_hybrid_never_returns_the_query_incident(retriever, corpus):
    _, incidents = corpus
    for incident_id in incidents["incident_id"].head(15):
        assert all(h.incident_id != incident_id for h in retriever.similar(incident_id))


def test_hybrid_scores_are_ordered_and_bounded(retriever, corpus):
    _, incidents = corpus
    hits = retriever.similar(str(incidents["incident_id"].iloc[0]), k=5)
    scores = [h.score for h in hits]
    assert scores == sorted(scores, reverse=True)
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_hybrid_is_deterministic(retriever, corpus):
    _, incidents = corpus
    target = str(incidents["incident_id"].iloc[2])
    first = [(h.incident_id, h.score) for h in retriever.similar(target, k=5)]
    second = [(h.incident_id, h.score) for h in retriever.similar(target, k=5)]
    assert first == second


def test_a_shared_technique_boosts_the_candidate(retriever):
    """The metadata re-rank is multiplicative and applied after fusion, never folded into RRF."""
    retriever.facets["Q"] = IncidentFacets(techniques=frozenset({"T1566"}), category="c")
    retriever.facets["M"] = IncidentFacets(techniques=frozenset({"T1566"}), category="c")
    retriever.facets["N"] = IncidentFacets(techniques=frozenset({"T9999"}), category="z")

    matched, why = retriever._boost("Q", "M")
    unmatched, _ = retriever._boost("Q", "N")
    assert matched > unmatched
    assert matched == pytest.approx((1 + BOOSTS["mitre"]) * (1 + BOOSTS["category"]))
    assert any("MITRE" in w for w in why)


def test_an_unknown_incident_gets_no_boost(retriever):
    assert retriever._boost("nope-1", "nope-2") == (1.0, [])


def test_hybrid_explains_which_retriever_matched(retriever, corpus):
    _, incidents = corpus
    hits = retriever.similar(str(incidents["incident_id"].iloc[0]), k=5)
    assert all(h.why() for h in hits)


def test_hybrid_survives_a_save_load_round_trip(retriever, corpus, tmp_path):
    _, incidents = corpus
    retriever.save(tmp_path)
    reloaded = HybridRetriever.load(tmp_path)
    target = str(incidents["incident_id"].iloc[1])
    assert [h.incident_id for h in retriever.similar(target, k=5)] == [
        h.incident_id for h in reloaded.similar(target, k=5)
    ]


def test_an_unknown_query_returns_nothing_rather_than_raising(retriever):
    assert retriever.similar("INC-does-not-exist", k=5) == []


# --- leakage: the tests that protect every metric in the project ------------------------------

def test_no_retrieved_record_carries_a_label(retriever, corpus):
    _, incidents = corpus
    for incident_id in incidents["incident_id"].head(20):
        for hit in retriever.similar(incident_id, k=5):
            assert not hasattr(hit, "label")


def test_no_label_string_appears_in_a_retrieved_summary(retriever, corpus):
    _, incidents = corpus
    for incident_id in incidents["incident_id"].head(20):
        for hit in retriever.similar(incident_id, k=5):
            for label in ("TruePositive", "BenignPositive", "FalsePositive"):
                assert label not in hit.summary


def test_the_indexed_corpus_itself_contains_no_labels(corpus):
    """Belt and braces: check what was indexed, not only what comes back."""
    _, incidents = corpus
    for summary in incidents["summary"]:
        for label in ("TruePositive", "BenignPositive", "FalsePositive"):
            assert label not in summary


def test_the_facet_metadata_carries_no_label(retriever):
    for facets in retriever.facets.values():
        blob = f"{facets.category} {facets.detector} {' '.join(facets.techniques)}"
        for label in ("TruePositive", "BenignPositive", "FalsePositive"):
            assert label not in blob


def test_hybrid_satisfies_the_retriever_protocol(retriever):
    """The Investigation agent is unchanged from Day 3 — that is what freezing this bought."""
    from app.retrieval.base import Retriever

    assert isinstance(retriever, Retriever)
