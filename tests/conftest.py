from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.data import fixture, incidents as incidents_mod  # noqa: E402

FIXTURE_INCIDENTS = 60


@pytest.fixture(scope="session")
def evidence():
    """Small deterministic evidence table. Session-scoped: generation is pure, so sharing it
    between tests cannot leak state."""
    frame = fixture.generate(n_incidents=FIXTURE_INCIDENTS)
    return frame.sort_values(["incident_id", "alert_id", "evidence_id"]).reset_index(drop=True)


@pytest.fixture(scope="session")
def incident_table(evidence):
    return incidents_mod.aggregate(evidence)
