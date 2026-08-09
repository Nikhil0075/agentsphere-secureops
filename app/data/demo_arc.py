"""The six-case presentation arc: which incidents the demo narrates, and in what order.

Three different things in this codebase are called "demo", and conflating any two of them corrupts
either a metric or the presentation:

===================  =======================  ======  ================================================
concept              column                   size    purpose
===================  =======================  ======  ================================================
dataset split        ``split == "demo"``      ~10%    hash-band holdout, used by evaluation
showcase pool        ``is_showcase``          30      graph build, rehearsal, the 3-60 band disclosure
presentation arc     ``demo_rank`` 1..6       6       narration order only
===================  =======================  ======  ================================================

The arc is a **strict subset of the showcase pool** and is never a metric denominator. It exists
because 30 cases is not a story and prewarming 30 of them costs ~180 live model calls; six chosen
cases span all three labels, four categories, the full risk range, both baseline agreement and
disagreement, and both a tampered and an untampered proof path.

Selection is pinned-first with a deterministic predicate fallback. Pinning is what gives the demo
its narrative; the predicates are what stop the module from breaking on a rebuild with different
data (``--source fixture``, a different ``-n``). A role that resolves by predicate is reported as
such in the manifest rather than silently passing for the hand-picked case.

Note the constraint the predicates are written under: ``risk_score`` and ``baseline_label`` do not
exist yet at this point in the pipeline. They are attached at load time by
``app/services/scoring.py``, long after ``scripts/prepare_data.py`` has written the Parquet. So a
predicate may only reference the aggregated incident columns, and the one role that genuinely wants
the baseline — "the case the baseline gets wrong" — can only approximate it. That role is flagged
``proxy=True`` so the manifest says so out loud.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Final

import pandas as pd

#: How many roles the arc declares. Used by callers to report "N of EXPECTED resolved".
EXPECTED_ARC_SIZE: Final[int] = 6

Mask = Callable[[pd.DataFrame], "pd.Series"]


@dataclass(frozen=True)
class DemoRole:
    """One beat of the demo, and how to find an incident that plays it."""

    rank: int
    role: str
    #: The hand-picked incident. Wins whenever it is present in the build.
    pinned_id: str
    #: One ASCII sentence. Reused by the demo script, the CLI and the Queue row tooltip, so it must
    #: survive a cp1252 Windows console.
    narration: str
    #: Boolean mask over the candidate frame, using aggregation-time columns only.
    predicate: Mask
    #: Tie-break ordering applied to the predicate's matches, as ``(column, ascending)`` pairs.
    order_by: tuple[tuple[str, bool], ...]
    #: True when the predicate only approximates the role. See the module docstring.
    proxy: bool = False
    #: Presentation contract for the deterministic gate. This is not a ground-truth label and is
    #: never shown to an agent; it only verifies that the six-case arc demonstrates both bounded
    #: autonomy and human authority after the workflow finishes.
    expected_auto_approved: bool = False


def _tp_initial_access_malicious(frame: pd.DataFrame) -> pd.Series:
    return (
        (frame["label"] == "TruePositive")
        & (frame["top_category"] == "InitialAccess")
        & (frame["max_last_verdict"] == "Malicious")
    )


def _tp_many_alerts(frame: pd.DataFrame) -> pd.Series:
    # Correlation collapse is driven by alert count: a single-alert incident has nothing to collapse.
    # Expressed as an ordering preference rather than a threshold -- a hard `alert_count >= 15`
    # matches nothing on the fixture corpus (max 5) and the role would go unresolved on every
    # build that is not the full GUIDE slice.
    return frame["label"] == "TruePositive"


def _tp_weak_verdict_heavy_evidence(frame: pd.DataFrame) -> pd.Series:
    # Proxy for "the baseline calls this benign and is wrong". A true positive whose strongest
    # verdict is only Suspicious is the shape that fools a feature model -- but the baseline does
    # not exist yet here, so this is a structural stand-in, not a measurement. Evidence weight is
    # again a preference, not a threshold, for the same portability reason as above.
    return (frame["label"] == "TruePositive") & (frame["max_last_verdict"] == "Suspicious")


def _bp_suspicious(frame: pd.DataFrame) -> pd.Series:
    return (frame["label"] == "BenignPositive") & (frame["max_suspicion_level"] == "Suspicious")


def _fp_discovery(frame: pd.DataFrame) -> pd.Series:
    return (frame["label"] == "FalsePositive") & (frame["top_category"] == "Discovery")


def _fp_exfiltration(frame: pd.DataFrame) -> pd.Series:
    return (frame["label"] == "FalsePositive") & (frame["top_category"] == "Exfiltration")


#: The arc, in narration order. Rank order is also risk-descending order on the current build,
#: which ``tests/test_demo_arc.py`` asserts against the scored table.
DEMO_ARC: Final[tuple[DemoRole, ...]] = (
    DemoRole(
        rank=1,
        role="high_risk_true_positive",
        pinned_id="INC-020335f5c65e",
        narration=(
            "Highest-risk true positive; agents and the baseline agree. This is the decision that "
            "gets anchored on Sepolia, tampered, and restored."
        ),
        predicate=_tp_initial_access_malicious,
        order_by=(("evidence_count", False), ("incident_id", True)),
        expected_auto_approved=False,
    ),
    DemoRole(
        rank=2,
        role="correlation_collapse",
        pinned_id="INC-0837694b8b09",
        narration="Twenty-one alerts collapse into ten clusters: alert fatigue, measured.",
        predicate=_tp_many_alerts,
        order_by=(("alert_count", False), ("incident_id", True)),
        expected_auto_approved=False,
    ),
    DemoRole(
        rank=3,
        role="baseline_disagreement",
        pinned_id="INC-0874da0f54ed",
        narration=(
            "A true positive the baseline calls benign. The verifier escalates and the gate "
            "demands a human."
        ),
        predicate=_tp_weak_verdict_heavy_evidence,
        order_by=(("evidence_count", False), ("incident_id", True)),
        proxy=True,
        expected_auto_approved=False,
    ),
    DemoRole(
        rank=4,
        role="benign_positive",
        pinned_id="INC-03c330695cea",
        narration="Real activity, authorised. Not every detection is an attack.",
        predicate=_bp_suspicious,
        order_by=(("evidence_count", False), ("incident_id", True)),
        expected_auto_approved=True,
    ),
    DemoRole(
        rank=5,
        role="low_risk_false_positive",
        pinned_id="INC-0abdb2a523a5",
        narration="A low-risk false positive: the queue noise this system is meant to suppress.",
        predicate=_fp_discovery,
        order_by=(("evidence_count", True), ("incident_id", True)),
        expected_auto_approved=True,
    ),
    DemoRole(
        rank=6,
        role="lowest_risk_exfil",
        pinned_id="INC-1010bda7f63d",
        narration="The bottom of the risk range, in a fourth attack category.",
        predicate=_fp_exfiltration,
        order_by=(("evidence_count", True), ("incident_id", True)),
        expected_auto_approved=False,
    ),
)

ARC_BY_RANK: Final[dict[int, DemoRole]] = {role.rank: role for role in DEMO_ARC}
ARC_BY_ROLE: Final[dict[str, DemoRole]] = {role.role: role for role in DEMO_ARC}


@dataclass(frozen=True)
class ArcResolution:
    """Which incident plays which role, and how each one was found."""

    #: incident_id -> (rank, role)
    assignments: dict[str, tuple[int, str]] = field(default_factory=dict)
    #: Roles resolved by their pinned id.
    pinned: list[str] = field(default_factory=list)
    #: Roles resolved by their predicate because the pin was absent.
    fallback: list[str] = field(default_factory=list)
    #: Roles nothing matched. Their rank is simply never assigned.
    unresolved: list[str] = field(default_factory=list)
    #: Roles resolved by a ``proxy=True`` predicate, i.e. approximated rather than pinned.
    proxy_roles: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return len(self.assignments) == EXPECTED_ARC_SIZE

    def incident_for_rank(self, rank: int) -> str:
        for incident_id, (assigned_rank, _) in self.assignments.items():
            if assigned_rank == rank:
                return incident_id
        return ""


def resolve_arc(incident_table: pd.DataFrame) -> ArcResolution:
    """Assign each role an incident. Deterministic, and never assigns one incident twice.

    Two passes, in this order, because a predicate must never be able to steal a pin:

    1. every role claims its ``pinned_id`` if that incident is in the candidate frame;
    2. every still-unresolved role, in rank order, takes the first row its predicate matches.

    A claimed incident is removed from the frame, so role N cannot take role N-1's pick. Candidates
    are restricted to the showcase pool up front, which is what keeps the arc a strict subset.

    A role that matches nothing stays unassigned and its rank stays *unused*. Ranks are deliberately
    not compacted: ``demo_rank == 3`` must always mean the baseline-disagreement slot, whatever the
    build, or the demo script and the data disagree about what case 3 is.
    """
    if "is_showcase" in incident_table.columns:
        candidates = incident_table[incident_table["is_showcase"].astype(bool)].copy()
    else:
        candidates = incident_table.copy()

    candidates["incident_id"] = candidates["incident_id"].astype(str)
    available = set(candidates["incident_id"])

    assignments: dict[str, tuple[int, str]] = {}
    pinned: list[str] = []
    fallback: list[str] = []
    unresolved: list[str] = []
    proxy_roles: list[str] = []

    for role in DEMO_ARC:
        if role.pinned_id in available:
            assignments[role.pinned_id] = (role.rank, role.role)
            pinned.append(role.role)
            available.discard(role.pinned_id)

    for role in DEMO_ARC:
        if role.role in pinned:
            continue

        remaining = candidates[candidates["incident_id"].isin(available)]
        matches = remaining[role.predicate(remaining)] if len(remaining) else remaining
        if matches.empty:
            unresolved.append(role.role)
            continue

        columns = [column for column, _ in role.order_by]
        ascending = [order for _, order in role.order_by]
        ordered = matches.sort_values(columns, ascending=ascending, kind="mergesort")
        chosen = str(ordered.iloc[0]["incident_id"])

        assignments[chosen] = (role.rank, role.role)
        fallback.append(role.role)
        if role.proxy:
            proxy_roles.append(role.role)
        available.discard(chosen)

    return ArcResolution(
        assignments=assignments,
        pinned=pinned,
        fallback=fallback,
        unresolved=unresolved,
        proxy_roles=proxy_roles,
    )


def mark_demo_arc(incident_table: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Add ``demo_rank`` and ``demo_role`` columns, and return the manifest stats.

    ``demo_rank`` is nullable ``Int64`` rather than float, so an off-arc row renders as ``<NA>``
    instead of ``NaN``. That keeps ``prepare_data.content_hash`` (which hashes the CSV rendering)
    stable, so ``--verify-determinism`` still reproduces.
    """
    resolution = resolve_arc(incident_table)

    out = incident_table.copy()
    ranks = out["incident_id"].map(
        lambda value: resolution.assignments.get(str(value), (pd.NA, ""))[0]
    )
    out["demo_rank"] = pd.array(ranks, dtype="Int64")
    out["demo_role"] = out["incident_id"].map(
        lambda value: resolution.assignments.get(str(value), (pd.NA, ""))[1]
    )

    resolved_by = {role: "pin" for role in resolution.pinned}
    resolved_by.update({role: "predicate" for role in resolution.fallback})

    by_rank: dict[str, dict[str, Any]] = {}
    for incident_id, (rank, role) in sorted(resolution.assignments.items(), key=lambda item: item[1][0]):
        row = out[out["incident_id"] == incident_id].iloc[0]
        by_rank[str(rank)] = {
            "incident_id": incident_id,
            "role": role,
            "label": str(row["label"]),
            "top_category": str(row["top_category"]),
            "evidence_count": int(row["evidence_count"]),
            "resolved_by": resolved_by.get(role, "pin"),
            "narration": ARC_BY_ROLE[role].narration,
        }

    stats = {
        "size": len(resolution.assignments),
        "expected": EXPECTED_ARC_SIZE,
        "complete": resolution.complete,
        "pinned": resolution.pinned,
        "fallback": resolution.fallback,
        "unresolved": resolution.unresolved,
        "proxy_roles": resolution.proxy_roles,
        "by_rank": by_rank,
        "selection": (
            "pinned incident ids with a deterministic role-predicate fallback; always a strict "
            "subset of is_showcase, and never used as a metric denominator"
        ),
    }
    return out, stats
