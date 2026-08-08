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


#: Columns added to schema.sql after a database may already exist on disk.
#:
#: `CREATE TABLE IF NOT EXISTS` does nothing to a table that is already there, so a column added to
#: schema.sql never reaches a developer's or a demo laptop's existing database. This is additive
#: only and is deliberately not a migration framework: it may add a column and nothing else. A
#: rename, a retype or a drop needs a real migration and a rebuilt database.
_ADDITIVE_COLUMNS: dict[str, dict[str, str]] = {
    # Why a failed anchor stores anything at all: the RPC reason ("insufficient funds for
    # gas * price + value") lived only in the POST response, so a page reload -- or opening
    # Proof from the tab bar rather than straight after anchoring -- showed "Anchor failed"
    # with "no reason reported". The one fact that makes the failure actionable was the one
    # fact not persisted.
    "blockchain_proofs": {"gas_used": "INTEGER", "failure_reason": "TEXT"},
}


def _ensure_columns(conn: sqlite3.Connection) -> list[str]:
    """Add any column in :data:`_ADDITIVE_COLUMNS` the table does not already have."""
    added: list[str] = []
    for table, columns in _ADDITIVE_COLUMNS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue  # the table itself is absent; executescript will have just created it
        for name, declaration in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
                added.append(f"{table}.{name}")
    return added


def init_db(db_path: str | Path | None = None) -> Path:
    """Create every table. Idempotent."""
    ddl = SCHEMA_PATH.read_text(encoding="utf-8")
    with session(db_path) as conn:
        conn.executescript(ddl)
        _ensure_columns(conn)
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
                    canonical_evidence_payload(row),
                )
                for row in evidence.to_dict("records")
            ],
        )
        counts = {
            "incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "evidence": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
        }
    return counts


def canonical_evidence_payload(row: dict) -> str:
    """The canonical string form of one evidence row.

    Written to ``evidence.payload_json`` and hashed into the evidence digest. Both the writer and
    the integrity check call *this* function rather than each formatting a dict of their own —
    two independent serialisations that drift by one space would make every proof read as
    tampered for a reason that has nothing to do with tampering.
    """
    return json.dumps(
        {k: _scalar(v) for k, v in row.items()},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _scalar(value):
    """pandas/numpy scalars are not sqlite-bindable; normalise to Python types."""
    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, AttributeError):
            return str(value)
    return value
