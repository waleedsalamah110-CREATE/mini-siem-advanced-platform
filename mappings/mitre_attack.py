from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreMapping:
    tactic: str
    technique_id: str
    technique_name: str


# Minimal, human-readable MITRE mappings (enough for portfolio + interview discussion).
MITRE: dict[str, MitreMapping] = {
    "Brute Force Login Attempts": MitreMapping(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
    ),
    "Suspicious PowerShell Execution": MitreMapping(
        tactic="Execution",
        technique_id="T1059.001",
        technique_name="PowerShell",
    ),
    "Privilege Escalation / Admin Change": MitreMapping(
        tactic="Privilege Escalation",
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
    ),
    "Impossible Travel (Valid Accounts)": MitreMapping(
        tactic="Defense Evasion / Persistence (Context: Valid Accounts)",
        technique_id="T1078",
        technique_name="Valid Accounts",
    ),
}


def get_mapping(rule_name: str) -> MitreMapping | None:
    return MITRE.get(rule_name)

