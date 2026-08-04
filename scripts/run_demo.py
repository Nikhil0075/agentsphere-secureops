"""Run the agent workflow end to end.

    python scripts/run_demo.py                              # first showcase incident, offline
    python scripts/run_demo.py --incident INC-0837694b8b09
    python scripts/run_demo.py --backend openai
    python scripts/run_demo.py --all-showcase --quiet       # every showcase incident + metrics

The Day 3 exit criterion, executable: an incident goes from selection to a triage label with no
manual intervention, and scattered alerts visibly collapse into fewer clusters.

The default backend is ``deterministic`` — no network, no API key.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.llm import build_client  # noqa: E402
from app.blockchain.client import ChainClient  # noqa: E402
from app.config import ARTIFACTS, METRICS_DIR, ensure_dirs  # noqa: E402
from app.data import incidents as incidents_mod  # noqa: E402
from app.data import loader  # noqa: E402
from app.db import session as db  # noqa: E402
from app.observability.logging import persist_agent_run  # noqa: E402
from app.orchestration.workflow import Workflow, WorkflowResult  # noqa: E402
from app.retrieval import hybrid  # noqa: E402
from app.retrieval.base import EntityOverlapRetriever  # noqa: E402
from app.services import decisions, scoring  # noqa: E402

RUN_METRICS = METRICS_DIR / "workflow_runs.json"
INDEX_DIR = ARTIFACTS / "index"


def print_result(result: WorkflowResult) -> None:
    state = result.state
    print(f"\n{'=' * 74}")
    print(f"incident {state.incident_id}   workflow {state.workflow_id}")
    print("=" * 74)

    if result.context.correlation:
        c = result.context.correlation
        # ASCII only: the Windows console defaults to cp1252 and a stray arrow or ellipsis
        # crashes the run at the point where it is supposed to be showing off.
        print(
            f"\ncorrelation  {c.alert_count} alert(s) -> {c.cluster_count} cluster(s) "
            f"({c.reduction:.0%} reduction, largest {c.largest_cluster})"
        )
        for cluster in c.clusters[:3]:
            print(
                f"    {cluster.cluster_id}: {cluster.size} alert(s) linked by "
                f"{', '.join(cluster.linking_entities[:3]) or 'time proximity'}"
            )

    if state.baseline:
        print(
            f"\nbaseline     {state.baseline.label.value} "
            f"@ {state.baseline.confidence:.2f} ({state.baseline.model_name})"
        )

    print("\nagents")
    for run in state.runs:
        flag = "ok " if run.status == "ok" else run.status
        print(
            f"    {run.sequence}. {run.agent:14s} {flag:10s} {run.latency_ms:5d}ms  "
            f"attempts={run.attempts}  {run.output_hash[:18]}..."
        )

    if state.detection:
        print(f"\ndetection    severity {state.detection.severity_score:.2f}")
        print(f"             {state.detection.initial_reason[:200]}")
    if state.correlation:
        print(
            f"\ncorrelated   bundle {len(state.correlation.evidence_bundle)} evidence id(s), "
            f"{len(state.correlation.relationships)} relationship(s), "
            f"{len(state.correlation.timeline)} timeline event(s)"
        )
        for gap in state.correlation.missing_information[:3]:
            print(f"             gap: {gap}")
    if state.investigation:
        print(
            f"\ninvestigation {len(state.investigation.similar_cases)} similar case(s), "
            f"{len(state.investigation.mitre_mapping)} MITRE mapping(s)"
        )
        print(f"             {state.investigation.investigation_summary[:220]}")
    if state.triage:
        print(f"\nTRIAGE       {state.triage.label.value} @ {state.triage.confidence:.2f}")
        print(f"             cites {len(state.triage.supporting_evidence_ids)} evidence id(s)")
        print(f"             {state.triage.rationale[:260]}")

    if state.remediation:
        print(
            f"\nREMEDIATION  {state.remediation.recommended_action} "
            f"({state.remediation.action_risk.value} risk, simulated)"
        )
        print(f"             rollback: {state.remediation.rollback_plan[:150]}")

    if state.verifier:
        v = state.verifier
        passed = sum(1 for c in v.policy_checks if c.passed)
        print(f"\nVERIFIER     {v.verdict.value.upper()}  ({passed}/{len(v.policy_checks)} checks)")
        for contradiction in v.contradictions[:3]:
            print(f"             ! {contradiction[:150]}")
        print(f"             {v.reasoning[:220]}")

    if result.gate:
        g = result.gate
        print(
            f"\nPOLICY GATE  {'HUMAN APPROVAL REQUIRED' if g.requires_approval else 'auto-approved'}"
        )
        for check in g.checks:
            print(f"             [{'pass' if check.passed else 'FAIL'}] {check.policy_id}  {check.detail[:90]}")
        for reason in g.reasons[:4]:
            print(f"             -> {reason[:150]}")

    print(f"\nevidence hash {state.evidence_hash}")
    print(f"output hash   {state.output_hash}")
    if result.degraded_agents():
        print(f"\ndegraded: {', '.join(result.degraded_agents())}")


def print_anchor(conn, persisted, result, approver: str | None) -> None:
    """Anchor the decision, optionally record an approval, and try to finalise.

    The finalise attempt is the point: on a high-risk decision with no approval the contract
    reverts, and that revert is the control being demonstrated.
    """
    client = ChainClient.connect()
    print("\n--- chain ---")
    status = client.status()
    if not client.available:
        print(f"  chain unavailable: {status['reason']}")
        print("  (the workflow completed regardless; the proof panel degrades, nothing else)")
        return

    print(f"  network      {status['network']} (chainId {status['chain_id']})")
    print(f"  DecisionProof {status['decision_proof_address']}")

    anchor = decisions.anchor_decision(conn, persisted.decision_id, result, client)
    if not anchor.anchored:
        print(f"  submit FAILED: {anchor.reason}")
        return

    print(f"  submitted    decision #{anchor.decision_id} in block {anchor.block_number}")
    print(f"  tx           {anchor.tx_hash}")
    print(f"  gas used     {anchor.gas_used:,}")
    print(f"  agent        {anchor.agent_address}")
    if anchor.explorer_url:
        print(f"  explorer     {anchor.explorer_url}")

    onchain = client.get_decision(anchor.decision_id)
    print(f"  on-chain     {onchain['label']} / {onchain['risk']} risk / {onchain['state']}")

    verified = client.verify(
        anchor.decision_id, result.state.evidence_hash, result.state.output_hash
    )
    print(f"  verify()     {'VALID' if verified else 'MISMATCH'}")

    if approver:
        approval_hash = decisions.comment_hash_for(persisted.decision_id, conn)
        decisions.record_approval(
            conn, persisted.decision_id, approver, True, "approved from run_demo"
        )
        approval = client.approve_decision(
            anchor.decision_id, True, decisions.comment_hash_for(persisted.decision_id, conn)
        )
        if approval.anchored:
            print(f"  approved by  {approver} (tx {approval.tx_hash[:18]}...)")
        else:
            print(f"  approval FAILED: {approval.reason}")

    final = client.finalize_decision(anchor.decision_id)
    if final.anchored:
        print(f"  finalised    block {final.block_number}")
    elif final.blocked_by_policy:
        # Expected on a medium/high-risk decision with no approval. This is the exit criterion:
        # the *contract* refused, not the application layer.
        print(f"  finalise     BLOCKED by {final.error} - human approval required")
        print("               the contract refused; not the application layer")
    else:
        print(f"  finalise     failed: {final.reason[:140]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident", help="incident id; defaults to the first showcase case")
    parser.add_argument("--backend", choices=["deterministic", "openai", "cache"])
    parser.add_argument("--all-showcase", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="cap on --all-showcase")
    parser.add_argument("--no-persist", action="store_true", help="skip writing to SQLite")
    parser.add_argument("--quiet", action="store_true", help="summary only")
    parser.add_argument(
        "--anchor", action="store_true", help="write the decision proof on chain"
    )
    parser.add_argument(
        "--approve",
        metavar="ANALYST",
        help="record a human approval and finalise (implies --anchor)",
    )
    args = parser.parse_args()
    if args.approve:
        args.anchor = True

    ensure_dirs()
    evidence, incidents = loader.load_prepared()
    model = scoring.load_baseline()

    if "is_showcase" in incidents:
        showcase = incidents[incidents["is_showcase"]].sort_values("incident_id")
    else:
        showcase = incidents.head(10)

    if args.all_showcase:
        targets = showcase["incident_id"].tolist()
        if args.limit:
            targets = targets[: args.limit]
    elif args.incident:
        targets = [args.incident]
    else:
        if showcase.empty:
            print("no showcase incidents; run scripts/prepare_data.py", file=sys.stderr)
            return 1
        targets = [showcase["incident_id"].iloc[0]]

    client = build_client(args.backend)
    print(f"backend: {client.backend} ({getattr(client, 'model', '')})")

    # Prefer the prebuilt hybrid index; fall back to entity overlap when it has not been built.
    retriever = hybrid.load_if_available(INDEX_DIR)
    if retriever is None:
        print("no prebuilt index (run scripts/build_index.py); using entity overlap")
        retriever = EntityOverlapRetriever(evidence, incidents)
    else:
        print(f"retrieval: hybrid BM25+vector, RRF k={retriever.rrf_k}")
    workflow = Workflow(client=client, retriever=retriever)

    summaries = []
    for incident_id in targets:
        match = incidents[incidents["incident_id"] == incident_id]
        if match.empty:
            print(f"unknown incident {incident_id}", file=sys.stderr)
            return 1
        row = match.iloc[0]
        rows = incidents_mod.evidence_for(evidence, incident_id)

        result = workflow.run(row, rows, baseline_model=model)
        if not args.quiet:
            print_result(result)

        state = result.state
        correct = bool(state.triage) and state.triage.label.value == row["label"]
        summaries.append(
            {
                "incident_id": incident_id,
                "workflow_id": state.workflow_id,
                "predicted": state.triage.label.value if state.triage else "",
                "actual": row["label"],
                "correct": correct,
                "confidence": state.triage.confidence if state.triage else 0.0,
                "baseline": state.baseline.label.value if state.baseline else "",
                "alerts": result.context.correlation.alert_count if result.context.correlation else 0,
                "clusters": state.correlation_clusters,
                "latency_ms": result.total_latency_ms(),
                "degraded": result.degraded_agents(),
                "evidence_hash": state.evidence_hash,
                "output_hash": state.output_hash,
            }
        )

        if not args.no_persist:
            with db.session() as conn:
                conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
                for run in state.runs:
                    output = getattr(state, run.agent, None)
                    persist_agent_run(
                        conn,
                        state.workflow_id,
                        state.incident_id,
                        run,
                        json.dumps(output.model_dump(mode="json"), sort_keys=True)
                        if output
                        else "",
                    )

                persisted = decisions.save_decision(conn, result)
                summaries[-1]["decision_id"] = persisted.decision_id

                if args.anchor:
                    print_anchor(conn, persisted, result, args.approve)

    if len(summaries) > 1:
        correct = sum(1 for s in summaries if s["correct"])
        collapsed = sum(1 for s in summaries if s["clusters"] < s["alerts"])
        print(f"\n{'=' * 74}")
        print(f"{len(summaries)} incident(s)")
        print(f"  agreement with ground truth  {correct}/{len(summaries)} "
              f"({correct / len(summaries):.0%})")
        print(f"  alerts collapsed             {collapsed}/{len(summaries)}")
        print(f"  degraded runs                "
              f"{sum(1 for s in summaries if s['degraded'])}/{len(summaries)}")
        print(f"  mean latency                 "
              f"{sum(s['latency_ms'] for s in summaries) / len(summaries):.0f}ms")

    RUN_METRICS.write_text(
        json.dumps({"backend": client.backend, "runs": summaries}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"\nrun records -> {RUN_METRICS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
