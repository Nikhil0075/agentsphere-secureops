"""Single entry point for incident data, whatever the source.

Everything downstream imports from here and never from ``fixture`` or ``guide_loader`` directly,
so switching between synthetic and real GUIDE data is a config change and nothing more.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from app.config import DATA_PROCESSED, DATA_RAW, settings

EVIDENCE_PARQUET = DATA_PROCESSED / "evidence.parquet"
INCIDENTS_PARQUET = DATA_PROCESSED / "incidents.parquet"


def resolve_guide_path() -> str:
    """GUIDE location from config, or the marker written by scripts/download_data.py."""
    if settings.guide_path:
        return settings.guide_path
    marker = DATA_RAW / "GUIDE_PATH.txt"
    if marker.exists():
        return marker.read_text(encoding="utf-8").strip()
    raise FileNotFoundError(
        "No GUIDE dataset location. Run scripts/download_data.py or set GUIDE_PATH in .env."
    )


def load_raw(source: str | None = None, max_incidents: int | None = None) -> pd.DataFrame:
    """Evidence-level rows in canonical form, from the configured source."""
    source = source or settings.data_source
    limit = max_incidents if max_incidents is not None else settings.demo_incident_count

    if source == "fixture":
        from app.data import fixture

        return fixture.generate(n_incidents=limit)

    if source == "guide":
        from app.data import guide_loader

        return guide_loader.load(resolve_guide_path(), max_incidents=limit)

    raise ValueError(f"unknown DATA_SOURCE {source!r}; expected 'fixture' or 'guide'")


def load_prepared() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Read the prepared Parquet pair. Returns ``(evidence, incidents)``."""
    for path in (EVIDENCE_PARQUET, INCIDENTS_PARQUET):
        if not Path(path).exists():
            raise FileNotFoundError(
                f"{path} missing. Run: python scripts/prepare_data.py"
            )
    return pd.read_parquet(EVIDENCE_PARQUET), pd.read_parquet(INCIDENTS_PARQUET)
