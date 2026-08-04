"""Create the application database and load the prepared dataset into it.

    python scripts/init_db.py

Idempotent: re-running replaces the incident and evidence tables with the current contents of
``data/processed/``. Agent runs, decisions, approvals and proofs are left untouched.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.data import loader  # noqa: E402
from app.db import session as db  # noqa: E402


def main() -> int:
    evidence, incidents = loader.load_prepared()
    counts = db.load_dataset(incidents, evidence)
    print(f"database: {settings.resolved_db_path}")
    print(f"tables:   {', '.join(db.table_names())}")
    print(f"loaded:   {counts['incidents']} incidents, {counts['evidence']} evidence rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
