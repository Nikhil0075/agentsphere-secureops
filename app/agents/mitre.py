"""MITRE ATT&CK technique names, and the allowlist that stops the model inventing them.

This lives apart from :mod:`app.agents.investigation` for one reason: ``base.Agent`` needs the
allowlist to validate what the Investigation agent produced, and ``investigation`` already imports
``base``. Putting the table here breaks the cycle.

The list is deliberately small -- the techniques GUIDE actually tags, plus the common neighbours a
model reaches for. It is a *plausibility* filter, not a complete ATT&CK catalogue: its job is to
reject ``T9999``, not to adjudicate whether T1548 was the better mapping than T1068.
"""

from __future__ import annotations

from typing import Final

#: Minimal technique names so the mapping is readable without a network lookup. Unlisted
#: techniques are still emitted, with the id standing in for the name.
MITRE_NAMES: Final[dict[str, str]] = {
    "T1003": "OS Credential Dumping",
    "T1005": "Data from Local System",
    "T1016": "System Network Configuration Discovery",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1041": "Exfiltration Over C2 Channel",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1112": "Modify Registry",
    "T1204": "User Execution",
    "T1486": "Data Encrypted for Impact",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1562": "Impair Defenses",
    "T1566": "Phishing",
}

KNOWN_TECHNIQUES: Final[frozenset[str]] = frozenset(MITRE_NAMES)


def technique_name(technique_id: str) -> str:
    base = technique_id.split(".")[0]
    return MITRE_NAMES.get(technique_id) or MITRE_NAMES.get(base) or technique_id


def is_known_technique(technique_id: str) -> bool:
    """A sub-technique is known if its parent is: T1566.001 rides on T1566."""
    value = str(technique_id).strip()
    return bool(value) and (
        value in KNOWN_TECHNIQUES or value.split(".")[0] in KNOWN_TECHNIQUES
    )
