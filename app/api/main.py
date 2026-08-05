"""FastAPI application.

    uvicorn app.api.main:app --reload --port 8000

Serves the React frontend. Every route reads from the same modules the CLI does — there is no
API-only code path, so a demo driven through the browser and one driven through
``scripts/run_demo.py`` exercise identical logic.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.api import models, state as app_state
from app.api.state import AppState
from app.blockchain.hashing import hash_payload
from app.config import ARTIFACTS, DATA_PROCESSED, METRICS_DIR, settings
from app.data.schema import ENTITY_COLUMNS
from app.db import session as db
from app.graph import build as graph_build
from app.graph import traverse
from app.graph.confidence import ConfidenceModel
from app.observability.logging import persist_agent_run
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
    chain = st.chain().status()

    # masked_sentinels is a list of records, one per masked column.
    raw_sentinels = manifest.get("masked_sentinels") or []
    if isinstance(raw_sentinels, dict):
        sentinels = list(raw_sentinels.keys())
    else:
        sentinels = [
            str(s.get("column", s)) if isinstance(s, dict) else str(s) for s in raw_sentinels
        ]

    return models.DatasetInfo(
        source=manifest.get("source", settings.data_source),
        incidents=len(st.incidents),
        evidence_rows=len(st.evidence),
        labels={k: int(v) for k, v in st.incidents["label"].value_counts().items()},
        splits={k: int(v) for k, v in st.incidents["split"].value_counts().items()},
        sentinels_masked=sentinels,
        index_available=st.index_available,
        llm_backend=settings.llm_backend,
        chain=chain,
        witfoo=st.provenance.summary(),
    )


# --- incidents -------------------------------------------------------------------------------

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
        baseline_label=str(row.get("baseline_label", "") or ""),
        baseline_confidence=float(row.get("baseline_confidence", 0.0) or 0.0),
    )


@app.get("/api/incidents", response_model=list[models.IncidentSummary])
def incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    showcase_only: bool = False,
    label: str | None = None,
    search: str | None = None,
) -> list[models.IncidentSummary]:
    """Risk-ordered incident queue.

    Ordering comes from the same max-heap the CLI uses, so the analyst sees the queue the system
    actually works through, not a re-sorted approximation of it.
    """
    st = get_state()
    frame = st.incidents

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
    result = st.workflow(request.backend).run(row, rows, baseline_model=st.baseline)
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
        degraded_agents=result.degraded_agents(),
    )


# --- decisions, approval and proof -----------------------------------------------------------

@app.post("/api/decisions/{decision_id}/approve", response_model=models.ProofInfo)
def approve(decision_id: str, request: models.ApprovalRequest) -> models.ProofInfo:
    """Record a human decision, and mirror it on chain when one is reachable."""
    st = get_state()
    with db.session() as conn:
        row = conn.execute(
            "SELECT incident_id, evidence_hash, output_hash FROM decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"unknown decision {decision_id}")

        decisions_service.record_approval(
            conn, decision_id, request.analyst, request.approved, request.comment
        )
        client = st.chain()
        info = decisions_service.verify_decision(conn, decision_id, client)

        if client.available and info.get("onchain_decision_id"):
            comment_hash = decisions_service.comment_hash_for(decision_id, conn)
            client.approve_decision(
                int(info["onchain_decision_id"]), request.approved, comment_hash
            )
            if request.approved:
                client.finalize_decision(int(info["onchain_decision_id"]))
            info = decisions_service.verify_decision(conn, decision_id, client)

    return _proof_info(decision_id, info, st)


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
        conn.execute(
            """INSERT INTO blockchain_proofs (
                   proof_id, decision_id, chain_id, contract_address, tx_hash, block_number,
                   agent_address, evidence_hash, output_hash, onchain_state, anchored_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?, datetime('now'))""",
            (
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
                "submitted" if outcome.anchored else "unanchored",
            ),
        )
        conn.commit()
        info = decisions_service.verify_decision(conn, decision_id, client)

    return _proof_info(decision_id, info, st, reason=outcome.reason)


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


def _proof_info(decision_id: str, info: dict, st: AppState, reason: str = "") -> models.ProofInfo:
    from app.blockchain.client import EXPLORERS

    chain_id = info.get("chain_id")
    tx_hash = info.get("tx_hash") or ""
    base = EXPLORERS.get(chain_id or 0)
    return models.ProofInfo(
        decision_id=decision_id,
        found=bool(info.get("found")),
        anchored=bool(tx_hash),
        evidence_hash=info.get("evidence_hash") or "",
        output_hash=info.get("output_hash") or "",
        tx_hash=tx_hash,
        chain_id=chain_id,
        contract_address=info.get("contract_address") or "",
        onchain_decision_id=info.get("onchain_decision_id"),
        onchain_state=(
            (st.chain().get_decision(info["onchain_decision_id"]) or {}).get("state", "")
            if info.get("onchain_decision_id")
            else ""
        ),
        explorer_url=f"{base}/tx/{tx_hash}" if base and tx_hash else "",
        valid=info.get("valid"),
        chain_available=bool(info.get("chain_available")),
        reason=reason,
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
) -> list[models.WitFooIncident]:
    """WitFoo incidents, ordered by the dataset's own suspicion score."""
    store = get_state().provenance
    if not store.available:
        return []
    return [
        models.WitFooIncident(**row)
        for row in store.list_incidents(
            limit=limit, offset=offset, search=search or "", mo_name=mo_name or ""
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
    )


def _proof_stats() -> dict:
    """§13.2: the share of completed cases carrying digests that still verify.

    Every anchored decision is re-verified by recomputation, so this is a live integrity sweep
    over the whole database rather than a counter that was incremented at write time. It is slow
    in proportion to how many decisions exist, which at demo scale is nothing.
    """
    st = get_state()
    client = st.chain()
    with db.session() as conn:
        rows = conn.execute(
            """SELECT d.decision_id FROM decisions d
               JOIN blockchain_proofs p ON p.decision_id = d.decision_id
               WHERE p.output_hash IS NOT NULL AND p.output_hash != ''"""
        ).fetchall()
        total_decisions = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]

        valid = tampered = 0
        for (decision_id,) in rows:
            report = integrity.check(conn, decision_id, client)
            if report.valid is True:
                valid += 1
            elif report.valid is False:
                tampered += 1

    anchored = len(rows)
    return {
        "decisions": total_decisions,
        "anchored": anchored,
        "valid": valid,
        "tampered": tampered,
        "validity_rate": round(valid / anchored, 4) if anchored else None,
        "chain_available": client.available,
    }


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok" if STATE is not None else "loading"}
