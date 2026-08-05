"""Day 7 rehearsal: run the whole system end to end and report what actually happened.

    python scripts/rehearse.py
    python scripts/rehearse.py --backend cache --anchor

Covers the §14.3 definition of done and the ten-case sweep §Day-7 asks for: true positives,
benign positives, false positives, low confidence, an induced agent failure, verifier rejection,
an approval that blocks, and the tamper round trip.

Prints a pass/fail table. A red row here is a demo that will fail in front of judges, so this is
run until it is green three times from a cold start rather than once.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.llm import DeterministicClient, FailingClient, build_client  # noqa: E402
from app.blockchain.client import ChainClient  # noqa: E402
from app.config import ARTIFACTS, METRICS_DIR, ensure_dirs  # noqa: E402
from app.data import incidents as incidents_mod  # noqa: E402
from app.data import loader  # noqa: E402
from app.db import session as db  # noqa: E402
from app.observability.logging import persist_agent_run  # noqa: E402
from app.orchestration.workflow import AGENT_SEQUENCE, Workflow  # noqa: E402
from app.policies import engine  # noqa: E402
from app.retrieval import hybrid  # noqa: E402
from app.services import decisions as decisions_service  # noqa: E402
from app.services import integrity, scoring  # noqa: E402

INDEX_DIR = ARTIFACTS / "index"
OUT = METRICS_DIR / "rehearsal.json"


@dataclass
class Case:
    name: str
    passed: bool
    detail: str
    data: dict = field(default_factory=dict)


def _persist(conn, result) -> str:
    state = result.state
    for run in state.runs:
        output = getattr(state, run.agent, None)
        persist_agent_run(
            conn,
            state.workflow_id,
            state.incident_id,
            run,
            json.dumps(output.model_dump(mode="json"), sort_keys=True) if output else "",
        )
    return decisions_service.save_decision(conn, result).decision_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default="deterministic")
    parser.add_argument("--anchor", action="store_true", help="also exercise the chain")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    ensure_dirs()
    evidence, incidents = loader.load_prepared()
    model = scoring.load_baseline()
    retriever = hybrid.load_if_available(INDEX_DIR)
    workflow = Workflow(client=build_client(args.backend), retriever=retriever)

    showcase = (
        incidents[incidents["is_showcase"]] if "is_showcase" in incidents else incidents.head(30)
    ).sort_values("incident_id")

    cases: list[Case] = []
    seen_labels: dict[str, int] = {}
    latencies: list[int] = []

    print(f"backend {args.backend}; {len(showcase)} showcase incidents available\n")

    # --- 1..N: a spread of real incidents, end to end -------------------------------------
    with db.session() as conn:
        conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))

        for n, (_, row) in enumerate(showcase.head(args.limit).iterrows(), start=1):
            rows = incidents_mod.evidence_for(evidence, row["incident_id"])
            result = workflow.run(row, rows, baseline_model=model)
            state = result.state
            decision_id = _persist(conn, result)
            latencies.append(result.total_latency_ms())
            seen_labels[row["label"]] = seen_labels.get(row["label"], 0) + 1

            complete = all(getattr(state, a) is not None for a in AGENT_SEQUENCE)
            cited = set(state.triage.supporting_evidence_ids) <= set(
                state.correlation.evidence_bundle
            )
            cases.append(
                Case(
                    f"{n:02d} {row['incident_id']}",
                    complete and cited and bool(state.evidence_hash),
                    f"truth {row['label']:<15} -> {state.triage.label.value:<15} "
                    f"@{state.triage.confidence:.2f}  verifier={state.verifier.verdict.value:<9}"
                    f"approval={'yes' if state.requires_approval else 'no'}",
                    {"decision_id": decision_id, "incident_id": row["incident_id"]},
                )
            )

        # --- label coverage ---------------------------------------------------------------
        cases.append(
            Case(
                "covers all three labels",
                len(seen_labels) == 3,
                ", ".join(f"{k}={v}" for k, v in sorted(seen_labels.items())),
            )
        )

        # --- induced agent failure --------------------------------------------------------
        row = showcase.iloc[0]
        rows = incidents_mod.evidence_for(evidence, row["incident_id"])
        broken = Workflow(client=FailingClient(failures=99), retriever=retriever).run(
            row, rows, baseline_model=model
        )
        cases.append(
            Case(
                "agent failure degrades, does not abort",
                broken.state.triage is not None
                and len(broken.degraded_agents()) == len(AGENT_SEQUENCE)
                and broken.state.requires_approval,
                f"{len(broken.degraded_agents())} agents fell back; decision still produced; "
                f"approval required",
            )
        )

        # --- verifier rejection -----------------------------------------------------------
        from tests.fixtures import scenarios
        from app.agents.verifier import VerifierAgent
        from app.orchestration.context import IncidentContext

        context = IncidentContext.from_incident(row, rows)
        conflict = scenarios.conflict()
        conflict.verifier = VerifierAgent(DeterministicClient()).run(conflict, context=context)[0]
        gate = engine.evaluate(
            triage=conflict.triage,
            remediation=conflict.remediation,
            verifier=conflict.verifier,
            evidence_ids=conflict.correlation.evidence_bundle,
        )
        cases.append(
            Case(
                "verifier rejects the conflict scenario",
                conflict.verifier.verdict.value == "reject" and gate.requires_approval,
                f"verdict={conflict.verifier.verdict.value}, "
                f"{len(conflict.verifier.contradictions)} contradiction(s), gate blocks",
            )
        )

        # --- low confidence never auto-approves --------------------------------------------
        low = scenarios.true_positive()
        low.triage = low.triage.model_copy(update={"confidence": 0.31})
        low_gate = engine.evaluate(
            triage=low.triage,
            remediation=low.remediation,
            verifier=None,
            evidence_ids=low.correlation.evidence_bundle,
        )
        cases.append(
            Case(
                "low confidence requires a human",
                low_gate.requires_approval and not low_gate.auto_approved,
                f"0.31 confidence -> {', '.join(low_gate.failed_policies())}",
            )
        )

        # --- a clean low-risk closure may auto-approve --------------------------------------
        clean = scenarios.false_positive()
        clean.verifier = VerifierAgent(DeterministicClient()).run(clean, context=context)[0]
        clean_gate = engine.evaluate(
            triage=clean.triage,
            remediation=clean.remediation,
            verifier=clean.verifier,
            evidence_ids=clean.correlation.evidence_bundle,
        )
        cases.append(
            Case(
                "clean low-risk closure auto-approves",
                clean_gate.auto_approved,
                "a gate that never says yes is not a gate, it is a stop sign",
            )
        )

        # --- tamper round trip --------------------------------------------------------------
        target = cases[0].data["decision_id"]
        target_wf = conn.execute(
            "SELECT workflow_id FROM decisions WHERE decision_id = ?", (target,)
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO blockchain_proofs (proof_id, decision_id, evidence_hash, output_hash,
                                              onchain_state)
               SELECT 'PRF-rehearse', decision_id, evidence_hash, output_hash, 'local'
               FROM decisions WHERE decision_id = ?""",
            (target,),
        )
        conn.commit()

        before = integrity.check(conn, target)
        integrity.tamper(conn, target_wf, "triage")
        during = integrity.check(conn, target)
        integrity.restore(conn, target_wf)
        after = integrity.check(conn, target)

        cases.append(
            Case(
                "tamper round trip",
                before.valid is True and during.valid is False and after.valid is True,
                f"valid -> {'TAMPERED' if during.valid is False else 'not detected'} -> valid",
            )
        )
        conn.execute("DELETE FROM blockchain_proofs WHERE proof_id = 'PRF-rehearse'")
        conn.commit()

    # --- chain, when asked ------------------------------------------------------------------
    if args.anchor:
        client = ChainClient.connect()
        cases.append(
            Case(
                "chain reachable",
                client.available,
                client.status().get("network", "") or client.unavailable_reason,
            )
        )

    # --- report -------------------------------------------------------------------------
    print(f"{'case':<46} {'':4} detail")
    print("-" * 118)
    for case in cases:
        print(f"{case.name:<46} {'PASS' if case.passed else 'FAIL'} {case.detail}")
    print("-" * 118)

    passed = sum(1 for c in cases if c.passed)
    mean_latency = sum(latencies) / len(latencies) if latencies else 0
    print(f"\n{passed}/{len(cases)} passed   mean workflow latency {mean_latency:.0f}ms")

    OUT.write_text(
        json.dumps(
            {
                "backend": args.backend,
                "passed": passed,
                "total": len(cases),
                "mean_latency_ms": round(mean_latency, 1),
                "cases": [
                    {"name": c.name, "passed": c.passed, "detail": c.detail} for c in cases
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"report -> {OUT}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
