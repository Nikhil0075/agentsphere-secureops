"""Sentinel detection.

The failure this guards against is specific: GUIDE fills unused entity columns with a single
placeholder integer, and leaving it in place would connect every incident through one fake node —
collapsing Union-Find to a single component and making BFS traverse the whole graph from anywhere.
"""

from __future__ import annotations

import pandas as pd

from app.data import sentinels


def _column(dominant: str, dominant_n: int, others: int) -> pd.DataFrame:
    values = [dominant] * dominant_n + [f"real-{i}" for i in range(others)]
    return pd.DataFrame({"device_id": values})


def test_detects_a_dominant_placeholder():
    frame = _column("98799", 980, 200)
    found = sentinels.detect(frame, columns=["device_id"])
    assert len(found) == 1
    assert found[0].value == "98799"
    assert found[0].share > 0.8


def test_ignores_a_merely_busy_value():
    """A shared asset appearing on 30% of rows is real signal, not a placeholder."""
    frame = _column("shared-jump-host", 300, 700)
    assert sentinels.detect(frame, columns=["device_id"]) == []


def test_ignores_a_dominant_value_without_dominance_over_the_runner_up():
    values = ["a"] * 600 + ["b"] * 400
    frame = pd.DataFrame({"device_id": values})
    assert sentinels.detect(frame, columns=["device_id"]) == []


def test_skips_columns_with_too_little_data():
    frame = pd.DataFrame({"device_id": ["x"] * 10})
    assert sentinels.detect(frame, columns=["device_id"]) == []


def test_mask_blanks_the_value_but_keeps_the_row():
    frame = _column("98799", 980, 20)
    found = sentinels.detect(frame, columns=["device_id"])
    masked = sentinels.mask(frame, found)
    assert len(masked) == len(frame)
    assert (masked["device_id"] == "").sum() == 980
    assert masked["device_id"].nunique() == 21  # 20 real values plus the blank


def test_mask_leaves_untouched_columns_alone():
    frame = _column("98799", 980, 20)
    frame["account_upn"] = "unaffected"
    found = sentinels.detect(frame, columns=["device_id"])
    masked = sentinels.mask(frame, found)
    assert (masked["account_upn"] == "unaffected").all()


def test_detect_and_mask_reports_what_it_did():
    frame = _column("98799", 980, 20)
    masked, report = sentinels.detect_and_mask(frame)
    assert report and report[0]["column"] == "device_id"
    assert set(report[0]) == {"column", "value", "share", "dominance"}
    assert (masked["device_id"] == "").any()


def test_masking_prevents_a_single_giant_component():
    """The consequence, stated as a test rather than as a comment."""
    # Mirrors the real shape: ~9 in 10 rows carry the placeholder, one carries a real device.
    rows = []
    for incident in range(200):
        rows.extend(
            {"incident_id": f"INC-{incident}", "device_id": "98799"} for _ in range(9)
        )
        rows.append({"incident_id": f"INC-{incident}", "device_id": f"dev-{incident % 20}"})
    frame = pd.DataFrame(rows)

    unmasked_span = frame.groupby("device_id")["incident_id"].nunique().max()
    masked, _ = sentinels.detect_and_mask(frame)
    real = masked[masked["device_id"] != ""]
    masked_span = real.groupby("device_id")["incident_id"].nunique().max()

    assert unmasked_span == 200, "the placeholder should touch every incident"
    assert masked_span <= 10, "after masking, no single device should span the corpus"
