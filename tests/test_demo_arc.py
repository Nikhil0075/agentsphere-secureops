"""The six-case presentation arc resolves deterministically, and stays a subset of the showcase.

Two corpora are exercised on purpose. The fixture corpus contains none of the pinned GUIDE ids, so
every test over it runs the *fallback* path -- which is the path nobody would otherwise notice was
broken until a rebuild. The real corpus tests are guarded on the Parquet existing and check the
opposite property: that the pins win and nothing falls back.
"""

from __future__ import annotations

import pandas as pd
import pytest

from app.data import loader
from app.data.demo_arc import (
    ARC_BY_RANK,
    DEMO_ARC,
    EXPECTED_ARC_SIZE,
    mark_demo_arc,
    resolve_arc,
)
from scripts.prepare_data import mark_showcase

PINNED_IDS = [role.pinned_id for role in DEMO_ARC]


@pytest.fixture(scope="module")
def showcase_table(incident_table):
    """The fixture corpus with showcase markers, which is what ``resolve_arc`` expects."""
    return mark_showcase(incident_table)


@pytest.fixture(scope="module")
def real_incidents():
    if not loader.INCIDENTS_PARQUET.exists():
        pytest.skip("prepared corpus not built; run scripts/prepare_data.py")
    return pd.read_parquet(loader.INCIDENTS_PARQUET)


# --- the contract itself ---------------------------------------------------------------------


def test_the_arc_declares_six_distinct_roles_at_distinct_ranks():
    assert len(DEMO_ARC) == EXPECTED_ARC_SIZE
    assert len({role.rank for role in DEMO_ARC}) == EXPECTED_ARC_SIZE
    assert len({role.role for role in DEMO_ARC}) == EXPECTED_ARC_SIZE
    assert len({role.pinned_id for role in DEMO_ARC}) == EXPECTED_ARC_SIZE
    assert [role.rank for role in DEMO_ARC] == list(range(1, EXPECTED_ARC_SIZE + 1))


def test_narration_is_ascii():
    """Narration reaches the Windows console through scripts/run_demo.py, and it is cp1252."""
    for role in DEMO_ARC:
        role.narration.encode("ascii")


# --- fallback path, over the fixture corpus ---------------------------------------------------


def test_no_pinned_id_exists_in_the_fixture_corpus(showcase_table):
    """Guards the premise of every fallback test below."""
    assert not set(PINNED_IDS) & set(showcase_table["incident_id"])


def test_fallback_resolves_without_any_pin(showcase_table):
    resolution = resolve_arc(showcase_table)
    assert resolution.pinned == []
    assert resolution.assignments
    assert set(resolution.fallback) | set(resolution.unresolved) == {
        role.role for role in DEMO_ARC
    }


def test_resolution_is_deterministic(showcase_table):
    first = resolve_arc(showcase_table)
    second = resolve_arc(showcase_table)
    assert first.assignments == second.assignments
    assert first.fallback == second.fallback
    assert first.unresolved == second.unresolved


def test_no_incident_holds_two_ranks(showcase_table):
    resolution = resolve_arc(showcase_table)
    ranks = [rank for rank, _ in resolution.assignments.values()]
    roles = [role for _, role in resolution.assignments.values()]
    assert len(ranks) == len(set(ranks))
    assert len(roles) == len(set(roles))


def test_the_arc_is_always_a_subset_of_the_showcase_pool(showcase_table):
    resolution = resolve_arc(showcase_table)
    pool = set(showcase_table[showcase_table["is_showcase"]]["incident_id"])
    assert set(resolution.assignments) <= pool


def test_an_unresolvable_role_leaves_its_rank_unused_rather_than_compacting(showcase_table):
    """demo_rank == 3 must always mean the baseline-disagreement slot, on every build.

    Compacting would silently renumber the arc, and the demo script and the data would then
    disagree about which case is case 3.
    """
    without_false_positives = showcase_table[showcase_table["label"] != "FalsePositive"]
    resolution = resolve_arc(without_false_positives)

    fp_roles = {"low_risk_false_positive", "lowest_risk_exfil"}
    assert fp_roles <= set(resolution.unresolved)

    assigned_ranks = {rank for rank, _ in resolution.assignments.values()}
    assert 5 not in assigned_ranks and 6 not in assigned_ranks
    for _, (rank, role) in resolution.assignments.items():
        assert ARC_BY_RANK[rank].role == role


def test_a_role_whose_predicate_matches_nothing_does_not_steal_another_pick(showcase_table):
    resolution = resolve_arc(showcase_table[showcase_table["label"] == "FalsePositive"])
    for _, (rank, role) in resolution.assignments.items():
        assert ARC_BY_RANK[rank].role == role


# --- the marked frame -------------------------------------------------------------------------


def test_mark_demo_arc_uses_nullable_int_so_the_content_hash_stays_stable(showcase_table):
    """Int64 renders as <NA> in to_csv; float64 would render NaN and could drift the hash."""
    marked, _ = mark_demo_arc(showcase_table)
    assert marked["demo_rank"].dtype == "Int64"
    off_arc = marked[marked["demo_role"] == ""]
    assert off_arc["demo_rank"].isna().all()


def test_mark_demo_arc_reports_how_each_role_was_resolved(showcase_table):
    _, stats = mark_demo_arc(showcase_table)
    assert stats["expected"] == EXPECTED_ARC_SIZE
    assert stats["size"] == len(stats["by_rank"])
    assert stats["complete"] is (stats["size"] == EXPECTED_ARC_SIZE)
    for entry in stats["by_rank"].values():
        assert entry["resolved_by"] in {"pin", "predicate"}
        assert entry["narration"]


def test_marking_is_idempotent(showcase_table):
    once, _ = mark_demo_arc(showcase_table)
    twice, _ = mark_demo_arc(once)
    assert once["demo_rank"].tolist() == twice["demo_rank"].tolist()
    assert once["demo_role"].tolist() == twice["demo_role"].tolist()


# --- pinned path, over the real corpus ---------------------------------------------------------


def test_every_pinned_incident_resolves_by_pin_on_the_real_corpus(real_incidents):
    resolution = resolve_arc(real_incidents)
    assert resolution.complete, f"unresolved roles: {resolution.unresolved}"
    assert resolution.fallback == [], "a pin went missing; the demo narrative would change"
    assert resolution.proxy_roles == []
    assert set(resolution.assignments) == set(PINNED_IDS)


def test_a_missing_pin_falls_back_to_its_predicate(real_incidents):
    rank_one = DEMO_ARC[0]
    without_the_pin = real_incidents[real_incidents["incident_id"] != rank_one.pinned_id]

    resolution = resolve_arc(without_the_pin)
    assert rank_one.role in resolution.fallback
    assert rank_one.role not in resolution.unresolved
    assert resolution.incident_for_rank(1) != rank_one.pinned_id


def test_rank_order_is_risk_descending_order(real_incidents):
    """The arc is narrated highest-risk first, so rank and risk must not disagree on stage."""
    from app.services import scoring

    model = scoring.load_baseline()
    if model is None:
        pytest.skip("baseline not trained; run scripts/train_baseline.py")

    marked, _ = mark_demo_arc(real_incidents)
    scored = scoring.prepare_queue_table(marked, model)
    arc = scored[scored["demo_rank"].notna()].sort_values("demo_rank")

    assert len(arc) == EXPECTED_ARC_SIZE
    risks = arc["risk_score"].tolist()
    assert risks == sorted(risks, reverse=True), dict(zip(arc["incident_id"], risks))


def test_the_arc_spans_all_three_labels_and_several_categories(real_incidents):
    """The whole point of hand-picking: one case per beat, not six of the same shape."""
    marked, _ = mark_demo_arc(real_incidents)
    arc = marked[marked["demo_rank"].notna()]

    assert set(arc["label"]) == {"TruePositive", "BenignPositive", "FalsePositive"}
    assert len(set(arc["top_category"])) >= 4
