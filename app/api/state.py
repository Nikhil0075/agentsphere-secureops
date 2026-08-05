"""Process-wide resources for the API.

The corpus, baseline model, retrieval index and entity graph are loaded once at startup and shared
across requests. Loading them per request would make every call take minutes; the prebuilt Day 4
index is what makes startup tolerable at all.

The entity graph is the exception: building it over 591k evidence rows takes several minutes, so
it is built lazily per incident on the small subgraph a request actually needs, rather than once
over the whole corpus. A blast radius scoped to one incident does not need the other 4,999.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

import pandas as pd

from app.agents.llm import LLMClient, build_client
from app.blockchain.client import ChainClient
from app.config import ARTIFACTS, settings
from app.data import loader
from app.orchestration.workflow import Workflow
from app.retrieval import hybrid
from app.retrieval.base import EntityOverlapRetriever, Retriever
from app.services import provenance

INDEX_DIR = ARTIFACTS / "index"


@dataclass
class AppState:
    evidence: pd.DataFrame
    incidents: pd.DataFrame
    retriever: Retriever
    baseline: object | None = None
    index_available: bool = False
    #: WitFoo provenance. Empty when the dataset has not been downloaded; the rest of the system
    #: is unaffected either way.
    provenance: provenance.ProvenanceStore = field(default_factory=provenance.ProvenanceStore)
    _clients: dict[str, LLMClient] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "AppState":
        from app.db import session as db
        from app.services import scoring

        # Apply the schema on every start. It is all CREATE TABLE IF NOT EXISTS, so this is a
        # no-op on a current database and adds any table introduced since the file was created.
        # Without it, a database made before `tamper_log` existed fails the first verify with an
        # OperationalError rather than degrading.
        db.init_db()

        evidence, incidents = loader.load_prepared()

        # `risk_score` and the baseline prediction are derived, not stored: the prepared Parquet
        # is the dataset, and a risk score depends on hand-set weights that can change without
        # reprocessing 591k rows. Computed once here, at startup, reusing the same helpers the
        # CLI uses so the queue the analyst sees is the queue the system works through.
        # Order matters: the risk formula consumes the baseline's true-positive probability, so
        # the baseline has to be attached first. prepare_queue_table does both in that order.
        model = scoring.load_baseline()
        incidents = scoring.prepare_queue_table(incidents, model)

        retriever = hybrid.load_if_available(INDEX_DIR)
        index_available = retriever is not None
        if retriever is None:
            retriever = EntityOverlapRetriever(evidence, incidents)

        return cls(
            evidence=evidence,
            incidents=incidents,
            retriever=retriever,
            provenance=provenance.load_if_available(),
            baseline=model,
            index_available=index_available,
        )

    # --- lookups ------------------------------------------------------------------------

    def incident_row(self, incident_id: str) -> pd.Series | None:
        match = self.incidents[self.incidents["incident_id"] == incident_id]
        return None if match.empty else match.iloc[0]

    def evidence_for(self, incident_id: str) -> pd.DataFrame:
        return self.evidence[self.evidence["incident_id"] == incident_id].reset_index(drop=True)

    # --- workflow -----------------------------------------------------------------------

    def workflow(self, backend: str | None = None) -> Workflow:
        """One workflow per backend, reused. Agents are stateless; the client holds the cache."""
        key = backend or settings.llm_backend
        if key not in self._clients:
            self._clients[key] = build_client(key)
        return Workflow(client=self._clients[key], retriever=self.retriever)

    def chain(self) -> ChainClient:
        """Reconnected per call on purpose: a chain that comes back after a network drop should
        start working again without restarting the API."""
        return ChainClient.connect()


@lru_cache(maxsize=64)
def _cached_graph_key(incident_id: str) -> str:
    return incident_id


def incident_graph(state: AppState, incident_id: str):
    """Entity graph for a single incident.

    Scoped rather than corpus-wide because building the full graph takes minutes and a
    per-incident blast radius does not need it.
    """
    from app.graph import build as graph_build

    return graph_build.build(state.evidence_for(incident_id))
