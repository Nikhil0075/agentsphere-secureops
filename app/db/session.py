"""SQLite access. Thin on purpose — no ORM, no migration framework in a seven-day build."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pandas as pd

from app.config import settings

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else settings.resolved_db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def session(db_path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | Path | None = None) -> Path:
    """Create every table. Idempotent."""
    ddl = SCHEMA_PATH.read_text(encoding="utf-8")
    with session(db_path) as conn:
        conn.executescript(ddl)
    return Path(db_path) if db_path else settings.resolved_db_path


def table_names(db_path: str | Path | None = None) -> list[str]:
    with session(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            " ORDER BY name"
        ).fetchall()
    return [r["name"] for r in rows]


def load_dataset(
    incidents: pd.DataFrame,
    evidence: pd.DataFrame,
    db_path: str | Path | None = None,
) -> dict[str, int]:
    """Populate ``incidents`` and ``evidence`` from the prepared Parquet tables.

    Replaces both tables wholesale — the prepared dataset is deterministic, so a partial load
    would only create a state that no script can reproduce.
    """
    incident_cols = [
        "incident_id",
        "org_id",
        "incident_ref",
        "label",
        "split",
        "first_seen",
        "last_seen",
        "alert_count",
        "evidence_count",
        "top_category",
        "top_detector",
        "top_alert_title",
        "mitre_techniques",
        "summary",
    ]
    with session(db_path) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.execute("DELETE FROM evidence")
        conn.execute("DELETE FROM incidents")

        conn.executemany(
            f"INSERT INTO incidents ({', '.join(incident_cols)}) "
            f"VALUES ({', '.join('?' * len(incident_cols))})",
            [
                tuple(
                    None if pd.isna(row.get(c)) else _scalar(row.get(c))
                    for c in incident_cols
                )
                for row in incidents.to_dict("records")
            ],
        )

        conn.executemany(
            "INSERT INTO evidence (evidence_id, incident_id, alert_id, timestamp, entity_type,"
            " evidence_role, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    row["evidence_id"],
                    row["incident_id"],
                    row.get("alert_id"),
                    row.get("timestamp"),
                    row.get("entity_type"),
                    row.get("evidence_role"),
                    json.dumps(
                        {k: _scalar(v) for k, v in row.items()},
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ),
                )
                for row in evidence.to_dict("records")
            ],
        )
        counts = {
            "incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "evidence": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
        }
    return counts


def _scalar(value):
    """pandas/numpy scalars are not sqlite-bindable; normalise to Python types."""
    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, AttributeError):
            return str(value)
    return value
