"""Day 1 guarantees: the schema holds, the split is deterministic and nothing leaks the label."""

from __future__ import annotations

import pandas as pd

from app.data import fixture, ids, incidents as incidents_mod
from app.data.schema import (
    CANONICAL_COLUMNS,
    ENTITY_COLUMNS,
    LABELS,
    REQUIRED_COLUMNS,
    SPLIT_BANDS,
    split_for_bucket,
)
from app.data.summarize import build_evidence_block, build_incident_summary
from scripts.prepare_data import content_hash, drop_unusable


def test_canonical_columns_present(evidence):
    for column in CANONICAL_COLUMNS:
        assert column in evidence.columns, f"missing canonical column {column}"
    for column in ("incident_id", "alert_id", "evidence_id"):
        assert column in evidence.columns


def test_required_columns_never_null(evidence):
    for column in REQUIRED_COLUMNS:
        assert evidence[column].notna().all()


def test_labels_are_in_the_closed_set(evidence, incident_table):
    assert set(evidence["label"]).issubset(set(LABELS))
    assert set(incident_table["label"]).issubset(set(LABELS))


def test_all_three_labels_represented(incident_table):
    # A dataset missing a class silently makes macro F1 meaningless.
    assert set(incident_table["label"]) == set(LABELS)


def test_evidence_ids_unique(evidence):
    assert evidence["evidence_id"].is_unique


def test_generation_is_deterministic():
    first = fixture.generate(n_incidents=25)
    second = fixture.generate(n_incidents=25)
    assert content_hash(first) == content_hash(second)


def test_prepared_content_hash_is_stable(evidence):
    """The Day 1 exit criterion, as a test rather than a claim."""
    a, _ = drop_unusable(evidence.copy())
    b, _ = drop_unusable(evidence.copy())
    assert content_hash(a) == content_hash(b)


def test_split_assignment_is_pure():
    for value in ("INC-abc123", "INC-000000000000", "INC-zzz"):
        assert ids.split_bucket(value) == ids.split_bucket(value)
        assert 0 <= ids.split_bucket(value) < 100


def test_split_bands_tile_the_range():
    covered = sorted(
        bucket for lo, hi in SPLIT_BANDS.values() for bucket in range(lo, hi)
    )
    assert covered == list(range(100))
    for bucket in (0, 69, 70, 89, 90, 99):
        assert split_for_bucket(bucket) in SPLIT_BANDS


def test_no_incident_appears_in_two_splits(incident_table):
    assert incident_table.groupby("incident_id")["split"].nunique().max() == 1


def test_every_evidence_row_maps_to_a_known_incident(evidence, incident_table):
    assert set(evidence["incident_id"]) == set(incident_table["incident_id"])


def test_aggregate_counts_match_the_evidence_table(evidence, incident_table):
    for _, row in incident_table.head(10).iterrows():
        rows = incidents_mod.evidence_for(evidence, row["incident_id"])
        assert row["evidence_count"] == len(rows)
        assert row["alert_count"] == rows["alert_id"].nunique()


def test_summary_is_pure(evidence, incident_table):
    row = incident_table.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    assert build_incident_summary(row, rows) == build_incident_summary(row, rows)


def test_summary_never_leaks_the_label(evidence, incident_table):
    for _, row in incident_table.iterrows():
        rows = incidents_mod.evidence_for(evidence, row["incident_id"])
        summary = build_incident_summary(row, rows)
        for label in LABELS:
            assert label not in summary


def test_summary_survives_a_dict_input(evidence, incident_table):
    row = incident_table.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    assert build_incident_summary(row.to_dict(), rows) == build_incident_summary(row, rows)


def test_evidence_block_cites_evidence_ids(evidence, incident_table):
    row = incident_table.iloc[0]
    rows = incidents_mod.evidence_for(evidence, row["incident_id"])
    block = build_evidence_block(rows)
    assert f"[{rows['evidence_id'].iloc[0]}]" in block


def test_drop_unusable_removes_duplicates_and_missing(evidence):
    dirty = pd.concat([evidence, evidence.head(3)], ignore_index=True)
    dirty.loc[dirty.index[-1], "incident_ref"] = None
    cleaned, stats = drop_unusable(dirty)
    assert stats["dropped_missing_required"] >= 1
    assert cleaned["evidence_id"].is_unique


def test_fixture_contains_a_hub_entity(evidence):
    """§8.4: hub nodes must exist in test data before Day 4 tries to cap traversal on them."""
    worst = 0
    for column in ENTITY_COLUMNS.values():
        subset = evidence[[column, "incident_id"]]
        subset = subset[subset[column].astype(str) != ""]
        if subset.empty:
            continue
        worst = max(worst, int(subset.groupby(column)["incident_id"].nunique().max()))
    assert worst >= 10, "no hub entity present; the BFS cap test would be vacuous"
