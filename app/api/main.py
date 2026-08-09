"""FastAPI application.

    uvicorn app.api.main:app --reload --port 8000

Serves the React frontend. Every route reads from the same modules the CLI does — there is no
API-only code path, so a demo driven through the browser and one driven through
``scripts/run_demo.py`` exercise identical logic.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from typing import Literal

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.api import models, state as app_state
from app.api.state import AppState
from app.agents.llm import ResponseCache, model_profile, normalize_mode
from app.blockchain.client import load_deployment
from app.blockchain.hashing import hash_payload
from app.config import ARTIFACTS, DATA_PROCESSED, LLM_CACHE_DIR, METRICS_DIR, settings
from app.data.schema import ENTITY_COLUMNS
from app.db import session as db
from app.graph import build as graph_build
from app.graph import traverse
from app.graph.confidence import ConfidenceModel
from app.observability.logging import persist_agent_run
from app.orchestration.workflow import AGENT_SEQUENCE
from app.policies import queue as incident_queue
from app.services import decisions as decisions_service
from app.services import integrity

STATE: AppState | None = None

#: Where the frontend dev server runs. Production serves the built bundle from the same origin.
DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global STATE
    STATE = AppState.load()
    yield
    STATE = None


app = FastAPI(
    title="AgentSphere SecureOps",
    version="0.5.0",
    description=(
        "A permissioned workforce of AI agents for SOC investigation, triage and verifiable "
        "response. All remediation is simulated."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DEV_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_state() -> AppState:
    if STATE is None:
        raise HTTPException(503, "corpus still loading")
    return STATE


def _read_json(path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


# --- dataset ---------------------------------------------------------------------------------

@app.get("/api/dataset", response_model=models.DatasetInfo)
def dataset() -> models.DatasetInfo:
    st = get_state()
    # The manifest records what was actually prepared. Reporting settings.data_source instead
    # would claim "fixture" while serving real GUIDE data, because .env still holds the value
    # used for an earlier run.
    manifest = _read_json(DATA_PROCESSED / "manifest.json")
    deployment = load_deployment() or {}
    chain = {
        "available": False,
        "availability": "unchecked",
        "reason": "Live contract availability is checked in Proof",
        "network": deployment.get("network", ""),
        "chain_id": deployment.get("chainId"),
        "registry_address": (deployment.get("contracts") or {}).get("AgentRegistry", {}).get("address", ""),
        "decision_proof_address": (deployment.get("contracts") or {}).get("DecisionProof", {}).get("address", ""),
        "agents": deployment.get("agents", {}),
    }

    # masked_sentinels is a list of records, one per masked column.
    raw_sentinels = manifest.get("masked_sentinels") or []
    if isinstance(raw_sentinels, dict):
        sentinels = list(raw_sentinels.keys())
    else:
        sentinels = [
            str(s.get("column", s)) if isinstance(s, dict) else str(s) for s in raw_sentinels
        ]

    # Read the arc from the manifest the build wrote rather than recounting the frame, so a stale
    # or incomplete arc reports as incomplete instead of silently looking fine.
    arc = manifest.get("demo_arc") or {}
    demo_arc = models.DemoArcInfo(
        size=int(arc.get("size", 0) or 0),
        expected=int(arc.get("expected", 6) or 6),
        complete=bool(arc.get("complete", False)),
        roles=[entry.get("role", "") for entry in (arc.get("by_rank") or {}).values()],
    )

    return models.DatasetInfo(
        source=manifest.get("source", settings.data_source),
        incidents=len(st.incidents),
        evidence_rows=len(st.evidence),
        labels={k: int(v) for k, v in st.incidents["label"].value_counts().items()},
        splits={k: int(v) for k, v in st.incidents["split"].value_counts().items()},
        showcase_incidents=int(manifest.get("showcase_incidents", 0) or 0),
        demo_arc=demo_arc,
        sentinels_masked=sentinels,
        index_available=st.index_available,
        llm_backend=settings.llm_backend,
        execution_mode=normalize_mode(settings.llm_backend),
        model_profile=model_profile(),
        replay_entries=len(ResponseCache(LLM_CACHE_DIR)),
        chain=chain,
        witfoo=st.provenance.summary(),
    )


# --- incidents -------------------------------------------------------------------------------

def _demo_rank(row) -> int | None:
    """``demo_rank`` is a nullable Int64 column, so an off-arc row arrives as pd.NA, not None."""
    value = row.get("demo_rank")
    if value is None or pd.isna(value):
        return None
    return int(value)


def _summary_row(row) -> models.IncidentSummary:
    return models.IncidentSummary(
        incident_id=row["incident_id"],
        label=str(row.get("label", "")),
        split=str(row.get("split", "")),
        risk_score=float(row.get("risk_score", 0.0) or 0.0),
        alert_count=int(row.get("alert_count", 0) or 0),
        evidence_count=int(row.get("evidence_count", 0) or 0),
        top_category=str(row.get("top_category", "") or ""),
        top_detector=str(row.get("top_detector", "") or ""),
        top_alert_title=str(row.get("top_alert_title", "") or ""),
        max_suspicion_level=str(row.get("max_suspicion_level", "") or ""),
        mitre_techniques=str(row.get("mitre_techniques", "") or ""),
        first_seen=str(row.get("first_seen", "") or ""),
        is_showcase=bool(row.get("is_showcase", False)),
        demo_rank=_demo_rank(row),
        demo_role=str(row.get("demo_role", "") or ""),
        baseline_label=str(row.get("baseline_label", "") or ""),
        baseline_confidence=float(row.get("baseline_confidence", 0.0) or 0.0),
    )


@app.get("/api/incidents", response_model=list[models.IncidentSummary])
def incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    showcase_only: bool = False,
    demo_only: bool = False,
    label: str | None = None,
    search: str | None = None,
) -> list[models.IncidentSummary]:
    """Risk-ordered incident queue.

    Ordering comes from the same max-heap the CLI uses, so the analyst sees the queue the system
    actually works through, not a re-sorted approximation of it.
    """
    st = get_state()
    frame = st.incidents

    if demo_only and "demo_rank" in frame:
        frame = frame[frame["demo_rank"].notna()]
    if showcase_only and "is_showcase" in frame:
        frame = frame[frame["is_showcase"]]
    if label:
        frame = frame[frame["label"] == label]
    if search:
        needle = search.lower()
        mask = frame["incident_id"].str.lower().str.contains(needle, na=False)
        if "summary" in frame:
            mask |= frame["summary"].str.lower().str.contains(needle, na=False)
        frame = frame[mask]

    # The same max-heap the CLI uses: top_k is O(n log k), so paging the queue never sorts the
    # whole corpus.
    ranked = incident_queue.from_frame(frame).top_k(offset + limit)
    return [_summary_row(item.payload) for item in ranked[offset : offset + limit]]


@app.get("/api/incidents/query", response_model=models.IncidentPage)
def query_incidents(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    showcase_only: bool = False,
    demo_only: bool = False,
    label: str | None = None,
    category: str | None = None,
    suspicion: str | None = None,
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    baseline_status: Literal["agree", "disagree", "unavailable"] | None = None,
    search: str | None = None,
    sort_by: Literal[
        "risk",
        "first_seen",
        "alerts",
        "evidence",
        "baseline_confidence",
        "incident",
        "demo_rank",
    ] = "risk",
    sort_dir: Literal["asc", "desc"] = "desc",
) -> models.IncidentPage:
    """Filter, sort and paginate the analyst queue over the entire incident corpus."""
    st = get_state()
    frame = st.incidents

    categories = sorted(
        value for value in frame.get("top_category", []).dropna().astype(str).unique() if value
    ) if "top_category" in frame else []
    suspicions = sorted(
        value
        for value in frame.get("max_suspicion_level", []).dropna().astype(str).unique()
        if value
    ) if "max_suspicion_level" in frame else []

    if demo_only and "demo_rank" in frame:
        frame = frame[frame["demo_rank"].notna()]
    if showcase_only and "is_showcase" in frame:
        frame = frame[frame["is_showcase"]]
    if label:
        frame = frame[frame["label"] == label]
    if category and "top_category" in frame:
        frame = frame[frame["top_category"] == category]
    if suspicion and "max_suspicion_level" in frame:
        frame = frame[frame["max_suspicion_level"] == suspicion]
    frame = frame[frame["risk_score"] >= min_risk]
    if baseline_status:
        available = frame["baseline_label"].fillna("").astype(str) != ""
        agrees = frame["baseline_label"] == frame["label"]
        if baseline_status == "agree":
            frame = frame[available & agrees]
        elif baseline_status == "disagree":
            frame = frame[available & ~agrees]
        else:
            frame = frame[~available]
    if search:
        needle = search.lower()
        mask = frame["incident_id"].astype(str).str.lower().str.contains(needle, na=False)
        for column in ("summary", "top_alert_title"):
            if column in frame:
                mask |= frame[column].astype(str).str.lower().str.contains(needle, na=False)
        frame = frame[mask]

    columns = {
        "risk": "risk_score",
        "first_seen": "first_seen",
        "alerts": "alert_count",
        "evidence": "evidence_count",
        "baseline_confidence": "baseline_confidence",
        "incident": "incident_id",
        "demo_rank": "demo_rank",
    }
    column = columns[sort_by]
    # A corpus prepared before the arc existed has no demo_rank column. Falling back beats a 500:
    # the queue still renders, just in its default order.
    if column not in frame:
        column = "risk_score"
    ascending = sort_dir == "asc"
    by = [column] if column == "incident_id" else [column, "incident_id"]
    directions = [ascending] if column == "incident_id" else [ascending, True]
    ordered = frame.sort_values(by, ascending=directions, kind="mergesort")
    total = len(ordered)
    page = ordered.iloc[offset : offset + limit]
    return models.IncidentPage(
        items=[_summary_row(row) for _, row in page.iterrows()],
        total=total,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_dir=sort_dir,
        facets=models.QueueFacets(categories=categories, suspicions=suspicions),
    )


@app.get("/api/incidents/{incident_id}", response_model=models.IncidentDetail)
def incident(incident_id: str) -> models.IncidentDetail:
    st = get_state()
    row = st.incident_row(incident_id)
    if row is None:
        raise HTTPException(404, f"unknown incident {incident_id}")

    rows = st.evidence_for(incident_id)
    counts: dict[str, int] = {}
    for entity_type, column in ENTITY_COLUMNS.items():
        if column in rows:
            values = rows[column].dropna().astype(str)
            n = int(values[values != ""].nunique())
            if n:
                counts[entity_type] = n

    base = _summary_row(row).model_dump()
    return models.IncidentDetail(
        **base,
        summary=str(row.get("summary", "") or ""),
        entity_counts=counts,
        threat_families=str(row.get("threat_families", "") or ""),
        duration_minutes=float(row.get("duration_minutes", 0.0) or 0.0),
    )


@app.get("/api/incidents/{incident_id}/evidence", response_model=list[models.EvidenceRow])
def evidence(incident_id: str, limit: int = Query(200, ge=1, le=2000)):
    st = get_state()
    rows = st.evidence_for(incident_id)
    if rows.empty:
        raise HTTPException(404, f"no evidence for {incident_id}")

    out = []
    for record in rows.head(limit).to_dict("records"):
        fields = {
            k: str(v)
            for k, v in record.items()
            if k in ENTITY_COLUMNS.values() and str(v or "").strip()
        }
        out.append(
            models.EvidenceRow(
                evidence_id=str(record["evidence_id"]),
                alert_id=str(record.get("alert_id", "") or ""),
                timestamp=str(record.get("timestamp", "") or ""),
                entity_type=str(record.get("entity_type", "") or ""),
                evidence_role=str(record.get("evidence_role", "") or ""),
                suspicion_level=str(record.get("suspicion_level", "") or ""),
                last_verdict=str(record.get("last_verdict", "") or ""),
                fields=fields,
            )
        )
    return out


@app.get("/api/incidents/{incident_id}/similar", response_model=list[models.SimilarIncident])
def similar(incident_id: str, k: int = Query(5, ge=1, le=20)):
    st = get_state()
    if st.incident_row(incident_id) is None:
        raise HTTPException(404, f"unknown incident {incident_id}")
    return [
        models.SimilarIncident(
            incident_id=hit.incident_id, score=hit.score, why=hit.why(), summary=hit.summary
        )
        for hit in st.retriever.similar(incident_id, k=k)
    ]


@app.get("/api/incidents/{incident_id}/graph", response_model=models.GraphInfo)
def graph(
    incident_id: str,
    max_hops: int = Query(2, ge=1, le=4),
    hub_degree: int = Query(150, ge=10),
):
    """Blast radius and the most probable attack chain within one incident."""
    st = get_state()
    rows = st.evidence_for(incident_id)
    if rows.empty:
        raise HTTPException(404, f"unknown incident {incident_id}")

    entity_graph = app_state.incident_graph(st, incident_id)
    nodes = entity_graph.nodes_for_incident(incident_id)
    if not nodes:
        return models.GraphInfo(
            blast_radius=models.BlastRadiusInfo(), node_count=0, edge_count=0
        )

    # Seed from the account or device with the widest local reach — the entity an analyst would
    # start from.
    seeds = sorted(nodes, key=lambda n: (-entity_graph.degree(n), n))[:2]
    radius = traverse.blast_radius(
        entity_graph, seeds, max_hops=max_hops, hub_degree=hub_degree, incident_id=incident_id
    )

    attack_path = None
    reached = radius.nodes
    if reached:
        model = ConfidenceModel(entity_graph, rows)
        path = traverse.most_probable_path(
            entity_graph, seeds[0], reached[-1], model.confidence, hub_degree=hub_degree
        )
        if path:
            attack_path = models.AttackPathInfo(**path.as_dict())

    payload = radius.as_dict()
    return models.GraphInfo(
        blast_radius=models.BlastRadiusInfo(
            seeds=payload["seeds"],
            impacted_by_type=payload["impacted_by_type"],
            total_nodes=payload["total_nodes"],
            hubs_blocked=payload["hubs_blocked"],
            truncated=payload["truncated"],
        ),
        attack_path=attack_path,
        node_count=entity_graph.node_count,
        edge_count=entity_graph.edge_count,
    )


# --- workflow --------------------------------------------------------------------------------

@app.post("/api/workflows", response_model=models.WorkflowResponse)
def run_workflow(request: models.WorkflowRequest) -> models.WorkflowResponse:
    """Run the six-agent chain, apply the policy gate, and persist the decision."""
    st = get_state()
    row = st.incident_row(request.incident_id)
    if row is None:
        raise HTTPException(404, f"unknown incident {request.incident_id}")

    rows = st.evidence_for(request.incident_id)
    mode = request.resolved_mode()
    result = st.workflow(mode).run(row, rows, baseline_model=st.baseline)
    s = result.state

    decision_id = ""
    if request.persist:
        with db.session() as conn:
            for run in s.runs:
                output = getattr(s, run.agent, None)
                persist_agent_run(
                    conn,
                    s.workflow_id,
                    s.incident_id,
                    run,
                    json.dumps(output.model_dump(mode="json"), sort_keys=True) if output else "",
                )
            decision_id = decisions_service.save_decision(conn, result).decision_id

    correlation_info = None
    if result.context.correlation:
        c = result.context.correlation
        correlation_info = models.CorrelationInfo(
            alert_count=c.alert_count,
            cluster_count=c.cluster_count,
            reduction=c.reduction,
            largest_cluster=c.largest_cluster,
            clusters=[
                models.ClusterInfo(
                    cluster_id=cl.cluster_id,
                    size=cl.size,
                    evidence_count=cl.evidence_count,
                    linking_entities=list(cl.linking_entities[:6]),
                )
                for cl in c.clusters[:20]
            ],
        )

    gate = None
    if result.gate:
        gate = models.GateInfo(
            requires_approval=result.gate.requires_approval,
            auto_approved=result.gate.auto_approved,
            action_risk=result.gate.action_risk,
            reasons=list(result.gate.reasons),
            checks=list(result.gate.checks),
        )

    cached_runs = [run for run in s.runs if run.cached]
    degraded = result.degraded_agents()
    if degraded:
        cache_status = "degraded"
    elif mode == "deterministic":
        cache_status = "bypassed"
    elif cached_runs and len(cached_runs) == len(s.runs):
        cache_status = "hit"
    else:
        cache_status = "miss_filled"

    return models.WorkflowResponse(
        workflow_id=s.workflow_id,
        incident_id=s.incident_id,
        decision_id=decision_id,
        label=s.triage.label.value if s.triage else "",
        confidence=s.triage.confidence if s.triage else 0.0,
        requires_approval=s.requires_approval,
        baseline=s.baseline,
        detection=s.detection,
        correlation=s.correlation,
        investigation=s.investigation,
        triage=s.triage,
        remediation=s.remediation,
        verifier=s.verifier,
        gate=gate,
        correlation_info=correlation_info,
        runs=list(s.runs),
        errors=list(s.errors),
        evidence_hash=s.evidence_hash,
        output_hash=s.output_hash,
        total_latency_ms=result.total_latency_ms(),
        traces=[models.AgentTrace(**trace) for trace in result.traces],
        degraded_agents=degraded,
        resampled_agents=result.resampled_agents(),
        revision_fired=result.revision_fired,
        execution_mode=mode,
        model_profile=model_profile(),
        cache_status=cache_status,
        trace_id=next((run.trace_id for run in s.runs if run.trace_id), ""),
        token_usage={
            "input": sum(run.prompt_tokens for run in s.runs),
            "output": sum(run.completion_tokens for run in s.runs),
            "total": sum(run.prompt_tokens + run.completion_tokens for run in s.runs),
        },
        retry_count=sum(max(0, run.attempts - 1) for run in s.runs)
        + max(0, len(s.runs) - len(AGENT_SEQUENCE)),
    )


# --- decisions, approval and proof -----------------------------------------------------------

@app.post("/api/decisions/{decision_id}/approve", response_model=models.ProofInfo)
def approve(decision_id: str, request: models.ApprovalRequest) -> models.ProofInfo:
    """Record a human decision, and mirror it on chain when one is reachable."""
    st = get_state()
    with db.session() as conn:
        row = conn.execute(
            """SELECT incident_id, evidence_hash, output_hash, action_risk
               FROM decisions WHERE decision_id = ?""",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"unknown decision {decision_id}")

        decisions_service.record_approval(
            conn, decision_id, request.analyst, request.approved, request.comment
        )
        client = st.chain()
        info = decisions_service.verify_decision(conn, decision_id, client)

        lifecycle_reason = ""
        if client.available and info.get("onchain_decision_id"):
            onchain_id = int(info["onchain_decision_id"])
            record = client.get_decision(onchain_id) or {}
            state, lifecycle_reason = decisions_service.advance_onchain_decision(
                client,
                onchain_id,
                row[3] or "high",
                approved=request.approved,
                comment_hash=decisions_service.comment_hash_for(decision_id, conn),
                initial_state=str(record.get("state", "") or ""),
            )
            decisions_service.update_onchain_state(conn, decision_id, onchain_id, state)
            info = decisions_service.verify_decision(conn, decision_id, client)

        attempts = _anchor_attempts(conn, decision_id)
        approval = _local_approval(conn, decision_id)

    return _proof_info(
        decision_id, info, st, attempts=attempts, approval=approval, client=client,
        reason=lifecycle_reason,
    )


@app.post("/api/decisions/{decision_id}/anchor", response_model=models.ProofInfo)
def anchor(decision_id: str) -> models.ProofInfo:
    """Write the decision's digests on chain."""
    st = get_state()
    with db.session() as conn:
        row = conn.execute(
            """SELECT incident_id, label, action_risk, evidence_hash, output_hash
               FROM decisions WHERE decision_id = ?""",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"unknown decision {decision_id}")

        client = st.chain()
        outcome = client.submit_decision(
            incident_id=row[0],
            evidence_hash=row[3],
            output_hash=row[4],
            label=row[1] or "Unknown",
            risk=row[2] or "high",
        )
        approval = _local_approval(conn, decision_id)
        lifecycle_reason = ""
        if outcome.anchored and outcome.decision_id:
            state, lifecycle_reason = decisions_service.advance_onchain_decision(
                client,
                int(outcome.decision_id),
                row[2] or "high",
                approved=approval.approved if approval is not None else None,
                comment_hash=approval.comment_hash if approval is not None else "",
                initial_state=outcome.onchain_state,
            )
            outcome.onchain_state = state
            if lifecycle_reason:
                outcome.reason = lifecycle_reason
        values = (
            # A content-derived id collides on retry: a failed anchor has no block number,
            # so a second attempt would reuse `PRF-<decision>-0` and blow up on the unique
            # constraint. Retrying after a network failure is the most likely thing anyone
            # does at a venue, and it must record another attempt rather than 500.
            f"PRF-{uuid.uuid4().hex[:12]}",
            decision_id,
            outcome.chain_id,
            outcome.contract_address,
            outcome.tx_hash,
            outcome.block_number,
            outcome.agent_address,
            row[3],
            row[4],
            (outcome.onchain_state or "proposed") if outcome.anchored else "unanchored",
            # A successful submission may still fail to advance approval/finalisation. Preserve
            # that narrower reason without misreporting the anchor itself as failed.
            outcome.reason or "",
        )
        try:
            conn.execute(
                """INSERT INTO blockchain_proofs (
                       proof_id, decision_id, chain_id, contract_address, tx_hash, block_number,
                       gas_used, agent_address, evidence_hash, output_hash, onchain_state,
                       onchain_decision_id, failure_reason, anchored_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))""",
                values[:6]
                + (outcome.gas_used,)
                + values[6:10]
                + (outcome.decision_id,)
                + values[10:],
            )
        except sqlite3.OperationalError:
            # A database created before gas_used existed. Record the anchor without it rather
            # than failing the demo; `python scripts/init_db.py` adds the column.
            conn.execute(
                """INSERT INTO blockchain_proofs (
                       proof_id, decision_id, chain_id, contract_address, tx_hash, block_number,
                       agent_address, evidence_hash, output_hash, onchain_state, anchored_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?, datetime('now'))""",
                values[:-1],
            )
        conn.commit()
        info = decisions_service.verify_decision(conn, decision_id, client)
        attempts = _anchor_attempts(conn, decision_id)
        approval = _local_approval(conn, decision_id)

    return _proof_info(
        decision_id, info, st, attempts=attempts, approval=approval,
        reason=outcome.reason, client=client
    )


@app.get("/api/decisions/{decision_id}/verify", response_model=models.IntegrityInfo)
def verify(decision_id: str) -> models.IntegrityInfo:
    """Recompute both digests from stored data and compare with the anchored proof.

    Genuinely recomputes — from ``agent_runs.output_json`` and ``evidence.payload_json`` — rather
    than reading back a stored hash column. ``valid: false`` means the off-chain record changed
    after anchoring.
    """
    st = get_state()
    with db.session() as conn:
        report = integrity.check(conn, decision_id, st.chain())
    if not report.found:
        raise HTTPException(404, f"unknown decision {decision_id}")
    return models.IntegrityInfo(**report.as_dict())


@app.post("/api/decisions/{decision_id}/tamper", response_model=models.TamperResult)
def tamper(decision_id: str, request: models.TamperRequest) -> models.TamperResult:
    """Edit a stored agent output, the way an insider with database access would.

    Touches only the application database. No hash column is updated and nothing on chain is
    altered, which is the entire point: the operator controls this table and controls nothing
    about the anchored digest.
    """
    st = get_state()
    with db.session() as conn:
        row = conn.execute(
            "SELECT workflow_id FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"unknown decision {decision_id}")
        try:
            change = integrity.tamper(conn, row[0], request.agent)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        report = integrity.check(conn, decision_id, st.chain())

    return models.TamperResult(
        decision_id=decision_id,
        agent=change["agent"],
        field=change["field"],
        before=str(change["before"]),
        after=str(change["after"]),
        integrity=models.IntegrityInfo(**report.as_dict()),
    )


@app.post("/api/decisions/{decision_id}/restore", response_model=models.TamperResult)
def restore(decision_id: str) -> models.TamperResult:
    """Undo every active tamper on this decision so the demo can be run again."""
    st = get_state()
    with db.session() as conn:
        row = conn.execute(
            "SELECT workflow_id FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"unknown decision {decision_id}")
        restored = integrity.restore(conn, row[0])
        report = integrity.check(conn, decision_id, st.chain())

    return models.TamperResult(
        decision_id=decision_id,
        agent="",
        field=f"restored {restored} tampered output(s)",
        before="",
        after="",
        integrity=models.IntegrityInfo(**report.as_dict()),
    )


def _anchor_attempts(conn, decision_id: str) -> list[models.AnchorAttempt]:
    """Every recorded anchor attempt for this decision, oldest first."""
    try:
        rows = conn.execute(
            """SELECT proof_id, tx_hash, block_number, gas_used, agent_address, onchain_state,
                      failure_reason, anchored_at
               FROM blockchain_proofs WHERE decision_id = ? ORDER BY created_at""",
            (decision_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        # Pre-gas_used database. Report the attempts without it rather than failing the page.
        rows = conn.execute(
            """SELECT proof_id, tx_hash, block_number, NULL AS gas_used, agent_address,
                      onchain_state, '' AS failure_reason, anchored_at
               FROM blockchain_proofs WHERE decision_id = ? ORDER BY created_at""",
            (decision_id,),
        ).fetchall()
    return [models.AnchorAttempt(**{key: row[key] for key in row.keys()}) for row in rows]


def _local_approval(conn, decision_id: str) -> models.LocalApproval | None:
    """The most recent human decision recorded for this decision, chain or no chain.

    Without this the Proof screen cannot tell an un-reviewed decision from a rejected one: the
    on-chain approver is empty in both cases, because a rejection that was never anchored has no
    transaction to carry it.
    """
    row = conn.execute(
        """SELECT approver, approved, comment_hash, created_at FROM approvals
           WHERE decision_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1""",
        (decision_id,),
    ).fetchone()
    if row is None:
        return None
    return models.LocalApproval(
        approver=row["approver"] or "",
        approved=bool(row["approved"]),
        comment_hash=row["comment_hash"] or "",
        recorded_at=row["created_at"] or "",
    )


def _proof_info(
    decision_id: str,
    info: dict,
    st: AppState,
    *,
    attempts: list[models.AnchorAttempt] | None = None,
    approval: models.LocalApproval | None = None,
    client=None,
    reason: str = "",
) -> models.ProofInfo:
    """Assemble the proof view.

    ``client`` is passed in rather than fetched: this used to call ``st.chain()`` inline while
    building the response, which opens a *second* connection mid-expression and puts an RPC on a
    display path. Callers that already hold a client hand it over; callers that do not get a
    chain-free answer.
    """
    from app.blockchain.client import EXPLORERS

    attempts = attempts or []
    latest = attempts[-1] if attempts else None
    deployment = load_deployment() or {}
    contracts = deployment.get("contracts") or {}

    chain_id = info.get("chain_id") or deployment.get("chainId")
    tx_hash = info.get("tx_hash") or ""
    base = EXPLORERS.get(chain_id or 0)

    onchain_id = info.get("onchain_decision_id")
    onchain: models.OnchainDecision | None = None
    onchain_state = ""
    if client is not None and onchain_id:
        record = client.get_decision(onchain_id) or {}
        if record:
            onchain = models.OnchainDecision(**record)
            onchain_state = record.get("state", "")
    if not onchain_state and latest is not None:
        onchain_state = latest.onchain_state or ""

    return models.ProofInfo(
        decision_id=decision_id,
        found=bool(info.get("found")),
        # A content-addressed retry may recover an existing on-chain decision without possessing
        # its original transaction hash. The contract id, not a local explorer link, proves the
        # submission exists.
        anchored=bool(tx_hash or onchain_id),
        evidence_hash=info.get("evidence_hash") or "",
        output_hash=info.get("output_hash") or "",
        tx_hash=tx_hash,
        # Declared on the model since day one and never populated on any route until now.
        block_number=latest.block_number if latest else None,
        gas_used=latest.gas_used if latest else None,
        chain_id=chain_id,
        contract_address=info.get("contract_address")
        or (contracts.get("DecisionProof") or {}).get("address", ""),
        registry_address=(contracts.get("AgentRegistry") or {}).get("address", ""),
        network=str(deployment.get("network", "") or ""),
        agent_address=latest.agent_address if latest else "",
        registered_agents=dict(deployment.get("agents") or {}),
        onchain_decision_id=onchain_id,
        onchain_state=onchain_state,
        explorer_url=f"{base}/tx/{tx_hash}" if base and tx_hash else "",
        valid=info.get("valid"),
        chain_available=bool(info.get("chain_available")),
        chain_checked=client is not None,
        onchain=onchain,
        attempts=attempts,
        approval=approval,
        # The live outcome when we have just submitted; otherwise whatever the last attempt
        # recorded. Without the fallback the page said "Anchor failed / no reason reported" on
        # every load except the one immediately following the POST.
        #
        # Gated on *that attempt's* own transaction hash rather than the aggregate one: a reason
        # belongs to the attempt that produced it, and an attempt that landed a transaction has
        # no failure to explain. Reading the aggregate would surface a stale reason next to a
        # successful anchor.
        reason=reason or (latest.failure_reason if latest and not latest.tx_hash else ""),
    )


@app.get("/api/decisions/{decision_id}/proof", response_model=models.ProofInfo)
def proof(decision_id: str, check_chain: bool = Query(False)) -> models.ProofInfo:
    """Everything known about this decision's anchor. Zero-RPC by default, and deliberately so.

    ``AppState.chain()`` reconnects on every call, so an unconditional connect on a route the UI
    opens on mount puts a public Sepolia RPC on the demo's critical path — the failure recorded in
    CLAUDE.md that took the API tests from 4s to 55s. Addresses, network and the registry come from
    ``artifacts/chain/deployment.json`` (a file read); tx hash, block, gas and state come from
    ``blockchain_proofs``. ``check_chain=true`` is the one explicit, user-initiated path that reads
    the contract, and the response says which of the two you got via ``chain_checked``.
    """
    with db.session() as conn:
        row = conn.execute(
            "SELECT evidence_hash, output_hash FROM decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"unknown decision {decision_id}")

        attempts = _anchor_attempts(conn, decision_id)
        approval = _local_approval(conn, decision_id)
        client = get_state().chain() if check_chain else None
        info = decisions_service.verify_decision(conn, decision_id, client)

    return _proof_info(
        decision_id, info, get_state(), attempts=attempts, approval=approval, client=client
    )


# --- witfoo provenance -------------------------------------------------------------------------
#
# A separate namespace on purpose. WitFoo carries threat assessments, GUIDE carries analyst triage
# verdicts, and the two must not end up in the same list where a reader could take them for the
# same thing. Every response here also carries the label note.

@app.get("/api/witfoo/incidents", response_model=list[models.WitFooIncident])
def witfoo_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str | None = None,
    mo_name: str | None = None,
    status: str | None = None,
    sort: str = Query("suspicion", pattern="^(suspicion|suspicion_asc|nodes|recent)$"),
) -> list[models.WitFooIncident]:
    """WitFoo incidents, filtered and ordered.

    Deliberately no threat-label filter: every shipped incident carries exactly one label and it
    is always ``malicious``. See ``ProvenanceStore.list_incidents``.
    """
    store = get_state().provenance
    if not store.available:
        return []
    return [
        models.WitFooIncident(**row)
        for row in store.list_incidents(
            limit=limit,
            offset=offset,
            search=search or "",
            mo_name=mo_name or "",
            status=status or "",
            sort=sort,
        )
    ]


@app.get("/api/witfoo/incidents/{incident_id}/graph", response_model=models.ProvenanceGraph)
def witfoo_graph(
    incident_id: str,
    max_hops: int = Query(3, ge=1, le=5),
    hub_degree: int = Query(150, ge=10),
) -> models.ProvenanceGraph:
    """One incident's provenance subgraph, plus a blast radius and attack path over it.

    The traversal calls are the *same* ones `/api/incidents/{id}/graph` makes. That reuse is the
    portability claim: the Day 4 graph layer never knew which dataset it was walking.
    """
    store = get_state().provenance
    incident = store.incident(incident_id)
    if incident is None:
        raise HTTPException(404, f"unknown WitFoo incident {incident_id}")

    subgraph = store.subgraph(incident_id)
    if subgraph is None:
        return models.ProvenanceGraph(incident=models.WitFooIncident(**incident))

    nodes = sorted(subgraph.graph.adjacency)
    edges = []
    for (src, dst), labels in subgraph.edge_labels.items():
        edges.append(
            models.ProvenanceEdge(
                source=graph_build.node_label(src),
                target=graph_build.node_label(dst),
                threat_label=labels.threat_label,
                confidence=labels.suspicion_score or labels.label_confidence,
                scored=labels.scored,
                attack_techniques=labels.attack_techniques,
            )
        )

    model = store.confidence_model(subgraph)
    seeds = sorted(nodes, key=lambda n: (-subgraph.graph.degree(n), n))[:2]
    radius = traverse.blast_radius(
        subgraph.graph, seeds, max_hops=max_hops, hub_degree=hub_degree
    )

    attack_path = None
    reached = radius.nodes
    if seeds and reached:
        path = traverse.most_probable_path(
            subgraph.graph, seeds[0], reached[-1], model.confidence, hub_degree=hub_degree
        )
        if path:
            attack_path = models.AttackPathInfo(**path.as_dict())

    payload = radius.as_dict()
    return models.ProvenanceGraph(
        incident=models.WitFooIncident(**incident),
        nodes=[graph_build.node_label(n) for n in nodes],
        edges=edges,
        blast_radius=models.BlastRadiusInfo(
            seeds=payload["seeds"],
            impacted_by_type=payload["impacted_by_type"],
            total_nodes=payload["total_nodes"],
            hubs_blocked=payload["hubs_blocked"],
            truncated=payload["truncated"],
        ),
        attack_path=attack_path,
        confidence_sources=model.source_breakdown(),
        node_count=subgraph.graph.node_count,
        edge_count=subgraph.graph.edge_count,
        edge_records=subgraph.edges_read,
    )


# --- metrics ---------------------------------------------------------------------------------

@app.get("/api/metrics", response_model=models.MetricsResponse)
def metrics() -> models.MetricsResponse:
    return models.MetricsResponse(
        baseline=_read_json(METRICS_DIR / "baseline.json"),
        evaluation=_read_json(METRICS_DIR / "evaluation.json"),
        graph=_read_json(ARTIFACTS / "graph" / "degree_stats.json"),
        index=_read_json(ARTIFACTS / "index" / "index_stats.json"),
        proofs=_proof_stats(),
        witfoo=get_state().provenance.summary(),
        # Both are local file reads, so the zero-RPC guarantee on this route is unaffected.
        variance=_read_json(METRICS_DIR / "variance.json"),
        rehearsal=_read_json(METRICS_DIR / "rehearsal.json"),
    )


def _proof_stats() -> models.ProofMetrics:
    """§13.2: the share of completed cases carrying digests that still verify.

    This aggregate deliberately performs a local sweep only. The verdict still recomputes both
    digests from evidence and agent outputs, while the independent contract read remains on the
    single-decision Proof screen. A decision counts once when any successful proof attempt has a
    transaction hash, so failed/offline attempts are excluded and retries cannot inflate it.
    """
    with db.session() as conn:
        rows = conn.execute(
            """SELECT DISTINCT d.decision_id FROM decisions d
               JOIN blockchain_proofs p ON p.decision_id = d.decision_id
               WHERE p.tx_hash IS NOT NULL AND p.tx_hash != ''
                 AND p.onchain_state IN ('submitted', 'approved', 'finalized')"""
        ).fetchall()
        total_decisions = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]

        valid = tampered = 0
        for (decision_id,) in rows:
            report = integrity.check(conn, decision_id)
            if report.valid is True:
                valid += 1
            elif report.valid is False:
                tampered += 1

    anchored = len(rows)
    return models.ProofMetrics(
        decisions=total_decisions,
        anchored=anchored,
        valid=valid,
        tampered=tampered,
        validity_rate=round(valid / anchored, 4) if anchored else None,
    )


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok" if STATE is not None else "loading"}
