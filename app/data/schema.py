"""The single column contract for incident data.

Microsoft GUIDE is an *evidence-level* dataset: one row is one piece of evidence, rows roll up
into alerts (``AlertId``), and alerts roll up into incidents (``IncidentId``). The triage label
``IncidentGrade`` is carried on every row of an incident.

Everything downstream — fixture generator, preparation script, entity graph, agents — speaks the
normalised names in :data:`CANONICAL_COLUMNS`, never the raw GUIDE names. That indirection is what
lets the synthetic fixture and the real dataset be interchangeable.
"""

from __future__ import annotations

from typing import Final

# --- labels -----------------------------------------------------------------------------------

LABELS: Final[tuple[str, ...]] = ("TruePositive", "BenignPositive", "FalsePositive")
LABEL_TO_INT: Final[dict[str, int]] = {name: i for i, name in enumerate(LABELS)}
INT_TO_LABEL: Final[dict[int, str]] = {i: name for name, i in LABEL_TO_INT.items()}

# --- raw GUIDE -> canonical -------------------------------------------------------------------
# Keys are the column names published on the Kaggle dataset card. Any key absent from the
# downloaded file is skipped with a warning rather than raising: the card and the shipped CSV have
# historically differed by a column or two, and a hard failure there would block the whole build.

GUIDE_COLUMN_MAP: Final[dict[str, str]] = {
    "Id": "evidence_row_id",
    "OrgId": "org_id",
    "IncidentId": "incident_ref",
    "AlertId": "alert_ref",
    "Timestamp": "timestamp",
    "DetectorId": "detector_id",
    "AlertTitle": "alert_title",
    "Category": "category",
    "MitreTechniques": "mitre_techniques",
    "IncidentGrade": "label",
    "ActionGrouped": "action_grouped",
    "ActionGranular": "action_granular",
    "EntityType": "entity_type",
    "EvidenceRole": "evidence_role",
    "SuspicionLevel": "suspicion_level",
    "LastVerdict": "last_verdict",
    "ThreatFamily": "threat_family",
    "DeviceId": "device_id",
    "DeviceName": "device_name",
    "Sha256": "file_sha256",
    "FileName": "file_name",
    "FolderPath": "folder_path",
    "IpAddress": "ip_address",
    "Url": "url",
    "AccountSid": "account_sid",
    "AccountUpn": "account_upn",
    "AccountName": "account_name",
    "AccountObjectId": "account_object_id",
    "NetworkMessageId": "mailbox_message_id",
    "EmailClusterId": "email_cluster_id",
    "RegistryKey": "registry_key",
    "ApplicationName": "application_name",
    "OSFamily": "os_family",
    "CountryCode": "country_code",
    "State": "state",
    "City": "city",
}

CANONICAL_COLUMNS: Final[tuple[str, ...]] = tuple(GUIDE_COLUMN_MAP.values())

#: Columns without which a row cannot be used at all.
REQUIRED_COLUMNS: Final[tuple[str, ...]] = (
    "incident_ref",
    "alert_ref",
    "label",
)

# --- entity extraction ---------------------------------------------------------------------
# Which canonical column supplies which entity-graph node type (§8.4). The graph is *built* from
# these; GUIDE does not ship one.

ENTITY_COLUMNS: Final[dict[str, str]] = {
    "account": "account_upn",
    "device": "device_id",
    "ip": "ip_address",
    "filehash": "file_sha256",
    "url": "url",
    "process": "file_name",
    "mailbox": "mailbox_message_id",
}

ENTITY_TYPES: Final[tuple[str, ...]] = tuple(ENTITY_COLUMNS)

# --- model features -------------------------------------------------------------------------
# Incident-level features for the non-LLM baseline (§6). Deliberately excludes anything derived
# from the label and anything the agents write, so there is no leakage path.

CATEGORICAL_FEATURES: Final[tuple[str, ...]] = (
    "top_category",
    "top_entity_type",
    "top_detector",
    "max_suspicion_level",
    "max_last_verdict",
)

NUMERIC_FEATURES: Final[tuple[str, ...]] = (
    "alert_count",
    "evidence_count",
    "distinct_entity_count",
    "distinct_account_count",
    "distinct_device_count",
    "distinct_ip_count",
    "distinct_filehash_count",
    "distinct_url_count",
    "mitre_technique_count",
    "distinct_category_count",
    "distinct_detector_count",
    "duration_minutes",
    "hour_of_day",
)

FEATURE_COLUMNS: Final[tuple[str, ...]] = NUMERIC_FEATURES + CATEGORICAL_FEATURES

# --- splits --------------------------------------------------------------------------------
#: Percentile bands over ``sha256(incident_id) % 100``. Deterministic, and an incident can never
#: appear in two splits.
SPLIT_BANDS: Final[dict[str, tuple[int, int]]] = {
    "train": (0, 70),
    "val": (70, 90),
    "demo": (90, 100),
}


def split_for_bucket(bucket: int) -> str:
    for name, (lo, hi) in SPLIT_BANDS.items():
        if lo <= bucket < hi:
            return name
    raise ValueError(f"bucket {bucket} outside 0-99")
