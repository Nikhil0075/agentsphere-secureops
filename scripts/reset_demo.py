"""Clear the local decision record so the next demo run starts clean.

    python scripts/reset_demo.py                  # dry run: report, change nothing
    python scripts/reset_demo.py --confirm        # clear
    python scripts/reset_demo.py --confirm -n 8   # and list 8 fresh candidates

**The chain is not reset, and cannot be.** ``submitDecision`` stores
``keccak256(incidentId, evidenceHash, outputHash)`` in a permanent mapping, so once an incident's
decision is anchored, re-anchoring it resolves to that record by fingerprint for ever. That is the
duplicate protection working, not a bug -- but it means an already-anchored incident can never
again produce a *new* transaction, and so never again shows a block number, gas figure or
transaction link on the Proof screen.

To demo a real anchor you therefore need an incident whose fingerprint the contract has not seen.
This script clears the local tables and then names incidents that qualify. The corpus has thousands,
so this is repeatable for as long as the demo needs.

Because clearing the database also destroys the only local record of what was anchored, the
incident ids are appended to a ledger under ``artifacts/chain/`` first. That directory is
git-ignored, so the ledger survives a reset without ever being published.

Evidence and incidents are left alone: they never change, they are expensive to rebuild, and the
replay cache is keyed on their content -- wiping them would force a paid re-warm for nothing.

Stdout is ASCII: the Windows console is cp1252.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ARTIFACTS  # noqa: E402
from app.db import session as db  # noqa: E402

#: Cleared by a reset, in an order that respects foreign keys where any exist.
DEMO_TABLES = ("tamper_log", "approvals", "blockchain_proofs", "agent_runs", "decisions")

#: Never cleared. Rebuilding these costs minutes and invalidates nothing that a demo cares about.
KEPT_TABLES = ("incidents", "evidence")

LEDGER = ARTIFACTS / "chain" / "anchored_incidents.json"


def load_ledger() -> set[str]:
    try:
        data = json.loads(LEDGER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(i) for i in data.get("incident_ids", [])}


def save_ledger(incident_ids: set[str]) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(
        json.dumps({"incident_ids": sorted(incident_ids)}, indent=2) + "\n", encoding="utf-8"
    )


def anchored_incidents(conn) -> set[str]:
    """Incidents with at least one recorded anchor attempt that reached the contract."""
    rows = conn.execute(
        """SELECT DISTINCT d.incident_id
           FROM decisions d
           JOIN blockchain_proofs p ON p.decision_id = d.decision_id
           WHERE COALESCE(p.onchain_decision_id, 0) > 0 OR COALESCE(p.tx_hash, '') <> ''"""
    ).fetchall()
    return {str(r[0]) for r in rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true", help="required; clears the tables")
    parser.add_argument(
        "-n", "--candidates", type=int, default=5, help="how many fresh incidents to name"
    )
    args = parser.parse_args()

    import pandas as pd

    from app.config import DATA_PROCESSED

    with db.session() as conn:
        counts = {}
        for table in DEMO_TABLES + KEPT_TABLES:
            try:
                counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except Exception:  # noqa: BLE001 - a missing table is not a reason to fail the reset
                counts[table] = 0
        seen = anchored_incidents(conn)

    ledger = load_ledger() | seen

    print("local record")
    for table in DEMO_TABLES:
        print(f"  {table:20s} {counts[table]:>8,}  -> cleared")
    for table in KEPT_TABLES:
        print(f"  {table:20s} {counts[table]:>8,}  -> kept")

    print(f"\nincidents anchored on chain: {len(ledger)}")
    print("  these can never produce a new transaction again -- the contract remembers the")
    print("  fingerprint, and re-anchoring resolves to the existing decision.")
    for incident_id in sorted(ledger):
        print(f"    {incident_id}")

    # Fresh candidates, preferring the curated showcase so the demo still has a good-looking case.
    fresh: list[str] = []
    try:
        frame = pd.read_parquet(DATA_PROCESSED / "incidents.parquet")
        pool = frame[frame["is_showcase"]] if "is_showcase" in frame else frame
        pool = pool[~pool["incident_id"].isin(ledger)]
        # Richest first. There is no `risk_score` column on the incident table -- risk is computed
        # by the queue at read time -- so evidence volume is the honest proxy available here, and
        # a case with more evidence gives the Workflow screen more to show.
        if "evidence_count" in pool:
            pool = pool.sort_values(["evidence_count", "incident_id"], ascending=[False, True])
        # A curated arc case that has never been anchored is the single best pick available: it is
        # the only kind that is *both* already warmed in the replay cache and still able to write a
        # real transaction. Surface those first rather than leaving the reader to notice.
        if "demo_rank" in pool:
            pool = pool.assign(is_arc=pool["demo_rank"].notna()).sort_values(
                ["is_arc", "evidence_count"] if "evidence_count" in pool else ["is_arc"],
                ascending=False,
            )
        fresh = [
            f"{row.incident_id}"
            + (f"   <- demo arc case {int(row.demo_rank)}, already warmed" if getattr(row, "is_arc", False) else "")
            for row in pool.head(args.candidates).itertuples()
        ]
        remaining = len(frame[~frame["incident_id"].isin(ledger)])
    except Exception as exc:  # noqa: BLE001 - the reset itself must not depend on the parquet
        print(f"\ncould not read the incident table ({type(exc).__name__}); skipping candidates")
        remaining = -1

    if fresh:
        print(f"\nnever anchored -- anchoring one of these writes a real transaction:")
        for incident_id in fresh:
            print(f"    {incident_id}")
        if remaining >= 0:
            print(f"  ({remaining:,} unanchored incidents in the corpus)")

    # Printed before the confirm gate as well: the backend choice is what the reader is deciding
    # right now, and learning it afterwards is learning it too late.
    _report_backend_advice()

    if not args.confirm:
        print("\ndry run; nothing was cleared. Re-run with --confirm.")
        return 2

    save_ledger(ledger)
    with db.session() as conn:
        for table in DEMO_TABLES:
            try:
                conn.execute(f"DELETE FROM {table}")
            except Exception as exc:  # noqa: BLE001
                print(f"  {table}: {type(exc).__name__}: {exc}", file=sys.stderr)
        conn.commit()

    with db.session() as conn:
        after = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in DEMO_TABLES}

    print("\ncleared:")
    for table in DEMO_TABLES:
        print(f"  {table:20s} {counts[table]:>8,} -> {after[table]:,}")
    print(f"\nledger -> {LEDGER}")
    return 0


def _report_backend_advice() -> None:
    """The trap that would otherwise ruin the reset demo.

    The replay cache is warmed per incident, and only the six curated arc cases are in it. Running
    a *fresh* incident under ``replay`` therefore misses on every stage, and a miss degrades to the
    conservative fallback -- six agents reporting ``fallback``, POL-006 blocking auto-approval, and
    a decision that looks broken on stage. The incident is fine; the cache has simply never seen it.
    """
    from app.agents.llm import ResponseCache, model_profile
    from app.config import LLM_CACHE_DIR

    try:
        entries = len(ResponseCache(LLM_CACHE_DIR))
    except Exception:  # noqa: BLE001 - advice must not be able to fail the reset
        entries = -1

    print("\nbefore demoing one of those, pick a backend:")
    print("  deterministic  works now: offline, no key, nothing to warm. The agents are")
    print("                 rule-based, so the decision is real and anchors for real.")
    print("  replay         ONLY the six curated arc cases are warmed. A fresh incident misses")
    print("                 every stage and degrades to fallback, which reads as a failure.")
    print("                 Warm first:  python scripts/prewarm_replay.py --pool showcase")
    print("  live           paid; needs a key and the network.")
    print(f"\ncache {entries} entries, active profile {model_profile()}")
    print("\nRun the workflow on a fresh incident, then anchor. The Proof tab will show a")
    print("transaction hash, a block number and gas used.")


if __name__ == "__main__":
    raise SystemExit(main())
