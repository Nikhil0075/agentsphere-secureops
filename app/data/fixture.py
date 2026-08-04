"""Schema-faithful synthetic incident data.

Purpose is narrow: let every downstream component be built and tested before the multi-gigabyte
GUIDE download finishes, and give the offline demo path a dataset that needs no credentials. It
emits the same canonical columns as :mod:`app.data.guide_loader`, so callers cannot tell them
apart.

Three properties are deliberately engineered in, because downstream code is built against them:

1. Alerts inside an incident share entities, so Union-Find has real components to collapse.
2. A handful of *hub* entities (a shared NAT egress IP, ``powershell.exe``, a service account)
   appear across many incidents. This is the §8.4 hub problem that freezes an uncapped BFS, and it
   must exist in test data before Day 4 tries to cap it.
3. Label-correlated signal is present but noisy, so the baseline classifier lands somewhere
   realistic rather than at 1.00 — a perfect baseline would tell us nothing.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pandas as pd

from app.data import ids
from app.data.schema import CANONICAL_COLUMNS, LABELS

_SEED = 20260804

_CATEGORIES = [
    "InitialAccess",
    "Execution",
    "Persistence",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Exfiltration",
    "CommandAndControl",
    "Impact",
    "SuspiciousActivity",
]

_MITRE = [
    "T1078",  # valid accounts
    "T1059",  # command and scripting interpreter
    "T1566",  # phishing
    "T1110",  # brute force
    "T1021",  # remote services
    "T1486",  # data encrypted for impact
    "T1041",  # exfiltration over C2
    "T1053",  # scheduled task
    "T1055",  # process injection
    "T1003",  # OS credential dumping
]

_ALERT_TITLES = [
    "Suspicious PowerShell command line",
    "Anomalous sign-in from unfamiliar location",
    "Malware detected on endpoint",
    "Multiple failed sign-in attempts",
    "Suspicious inbox forwarding rule",
    "Unusual volume of file downloads",
    "Connection to known malicious host",
    "Credential dumping tool behaviour",
    "Mass file encryption detected",
    "Impossible travel activity",
]

_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "wscript.exe",
    "mimikatz.exe",
    "svchost.exe",
    "chrome.exe",
    "outlook.exe",
]

_THREAT_FAMILIES = ["", "Emotet", "Qakbot", "Cobalt Strike", "AgentTesla", "LockBit"]
_SUSPICION = ["", "Suspicious", "Malicious", "Benign"]
_VERDICTS = ["", "Suspicious", "Malicious", "Clean", "NoThreatsFound"]
_ENTITY_ROLES = ["Impacted", "Related"]
_OS = ["Windows10", "Windows11", "WindowsServer2019", "Linux", "macOS"]

# Hubs — the entities that connect thousands of rows in a real SOC and blow up graph traversal.
_HUB_IP = "203.0.113.10"
_HUB_ACCOUNT = "svc-backup@contoso.com"
_HUB_PROCESS = "powershell.exe"


def _label_profile(rng: random.Random, label: str) -> dict:
    """Signal that separates the classes, with enough overlap to stay honest."""
    if label == "TruePositive":
        return {
            "alerts": rng.randint(2, 5),
            "evidence_per_alert": rng.randint(3, 7),
            "suspicion_weights": [0.05, 0.35, 0.50, 0.10],
            "verdict_weights": [0.05, 0.30, 0.50, 0.10, 0.05],
            "threat_family_p": 0.65,
            "mitre_count": rng.randint(2, 4),
        }
    if label == "BenignPositive":
        return {
            "alerts": rng.randint(1, 3),
            "evidence_per_alert": rng.randint(2, 5),
            "suspicion_weights": [0.10, 0.40, 0.15, 0.35],
            "verdict_weights": [0.10, 0.35, 0.10, 0.35, 0.10],
            "threat_family_p": 0.20,
            "mitre_count": rng.randint(1, 3),
        }
    return {  # FalsePositive
        "alerts": rng.randint(1, 2),
        "evidence_per_alert": rng.randint(1, 4),
        "suspicion_weights": [0.20, 0.25, 0.05, 0.50],
        "verdict_weights": [0.15, 0.20, 0.05, 0.45, 0.15],
        "threat_family_p": 0.05,
        "mitre_count": rng.randint(0, 2),
    }


def _pick(rng: random.Random, options: list[str], weights: list[float]) -> str:
    return rng.choices(options, weights=weights, k=1)[0]


def generate(n_incidents: int = 200, seed: int = _SEED) -> pd.DataFrame:
    """Return evidence-level rows in canonical column form."""
    rng = random.Random(seed)
    base_time = datetime(2026, 7, 1, tzinfo=timezone.utc)
    rows: list[dict] = []

    for i in range(n_incidents):
        # Skewed towards benign, as real SOC queues are.
        label = rng.choices(LABELS, weights=[0.30, 0.30, 0.40], k=1)[0]
        profile = _label_profile(rng, label)

        org_id = f"org-{i % 5}"
        incident_ref = 10_000 + i
        inc_id = ids.incident_id(org_id, incident_ref)
        incident_start = base_time + timedelta(hours=rng.randint(0, 24 * 30))

        # Entities shared across every alert in this incident — the reason Union-Find has work.
        shared_account = (
            _HUB_ACCOUNT if rng.random() < 0.12 else f"user{rng.randint(1, 60):03d}@contoso.com"
        )
        shared_device = f"dev-{rng.randint(1, 80):03d}"
        shared_ip = _HUB_IP if rng.random() < 0.18 else f"198.51.100.{rng.randint(1, 254)}"
        techniques = rng.sample(_MITRE, k=min(profile["mitre_count"], len(_MITRE)))
        detector = f"det-{rng.randint(1, 12):02d}"
        category = rng.choice(_CATEGORIES)

        for a in range(profile["alerts"]):
            alert_ref = incident_ref * 100 + a
            alert_id_value = ids.alert_id(org_id, incident_ref, alert_ref)
            alert_time = incident_start + timedelta(minutes=rng.randint(0, 180))
            alert_title = rng.choice(_ALERT_TITLES)

            for e in range(profile["evidence_per_alert"]):
                row_ref = f"{alert_ref}-{e}"
                process = (
                    _HUB_PROCESS if rng.random() < 0.30 else rng.choice(_PROCESSES)
                )
                has_file = rng.random() < 0.55
                has_url = rng.random() < 0.30
                has_mail = rng.random() < 0.20

                rows.append(
                    {
                        "evidence_row_id": ids.evidence_id(
                            org_id, incident_ref, alert_ref, row_ref
                        ),
                        "org_id": org_id,
                        "incident_ref": incident_ref,
                        "alert_ref": alert_ref,
                        "timestamp": (
                            alert_time + timedelta(seconds=rng.randint(0, 900))
                        ).isoformat(),
                        "detector_id": detector,
                        "alert_title": alert_title,
                        "category": category,
                        "mitre_techniques": ";".join(techniques),
                        "label": label,
                        "action_grouped": "",
                        "action_granular": "",
                        "entity_type": rng.choice(
                            ["Process", "Ip", "User", "Machine", "File", "Url", "MailMessage"]
                        ),
                        "evidence_role": rng.choice(_ENTITY_ROLES),
                        "suspicion_level": _pick(
                            rng, _SUSPICION, profile["suspicion_weights"]
                        ),
                        "last_verdict": _pick(rng, _VERDICTS, profile["verdict_weights"]),
                        "threat_family": (
                            rng.choice(_THREAT_FAMILIES[1:])
                            if rng.random() < profile["threat_family_p"]
                            else ""
                        ),
                        "device_id": shared_device,
                        "device_name": f"{shared_device}.contoso.local",
                        "file_sha256": (
                            f"{rng.getrandbits(256):064x}" if has_file else ""
                        ),
                        "file_name": process,
                        "folder_path": rng.choice(
                            [r"C:\Windows\System32", r"C:\Users\Public", r"C:\Temp"]
                        ),
                        "ip_address": shared_ip,
                        "url": (
                            f"http://cdn{rng.randint(1, 40)}.example-delivery.net/p"
                            if has_url
                            else ""
                        ),
                        "account_sid": f"S-1-5-21-{rng.randint(1000, 9999)}",
                        "account_upn": shared_account,
                        "account_name": shared_account.split("@")[0],
                        "account_object_id": f"aad-{rng.randint(100000, 999999)}",
                        "mailbox_message_id": (
                            f"msg-{rng.randint(100000, 999999)}" if has_mail else ""
                        ),
                        "email_cluster_id": "",
                        "registry_key": "",
                        "application_name": rng.choice(["", "Office365", "Teams", "Edge"]),
                        "os_family": rng.choice(_OS),
                        "country_code": rng.choice(["SG", "IN", "US", "DE", "AU"]),
                        "state": "",
                        "city": "",
                        # ids assigned here so nothing downstream has to re-derive them
                        "incident_id": inc_id,
                        "alert_id": alert_id_value,
                        "evidence_id": ids.evidence_id(
                            org_id, incident_ref, alert_ref, row_ref
                        ),
                    }
                )

    frame = pd.DataFrame(rows)
    ordered = list(CANONICAL_COLUMNS) + ["incident_id", "alert_id", "evidence_id"]
    return frame[ordered]
