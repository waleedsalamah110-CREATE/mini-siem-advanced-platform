from __future__ import annotations

from typing import Any, Callable

from config.settings import Settings
from mappings.mitre_attack import get_mapping

from .brute_force import detect as detect_brute_force
from .impossible_travel import detect as detect_impossible_travel
from .privilege_escalation import detect as detect_privilege_escalation
from .suspicious_powershell import detect as detect_suspicious_powershell


Detector = Callable[[list[dict[str, Any]], Settings], list[dict[str, Any]]]


def _enrich_with_mitre(alert: dict[str, Any]) -> dict[str, Any]:
    mapping = get_mapping(alert.get("rule_name", ""))
    if not mapping:
        alert["mitre_attack"] = None
        return alert

    alert["mitre_attack"] = {
        "tactic": mapping.tactic,
        "technique_id": mapping.technique_id,
        "technique_name": mapping.technique_name,
    }
    return alert


def run_all_detections(events: list[dict[str, Any]], settings: Settings) -> list[dict[str, Any]]:
    detectors: list[Detector] = [
        detect_brute_force,
        detect_suspicious_powershell,
        detect_privilege_escalation,
        detect_impossible_travel,
    ]

    alerts: list[dict[str, Any]] = []
    for detect in detectors:
        alerts.extend(detect(events, settings))

    # MITRE enrichment (centralized so rules stay focused on detection logic).
    alerts = [_enrich_with_mitre(a) for a in alerts]

    # Stable ordering for output/reporting: by severity then timestamp.
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    alerts.sort(
        key=lambda a: (
            severity_rank.get(a.get("severity", "Info"), 99),
            a.get("event_timestamp") or "",
            a.get("created_at") or "",
        )
    )
    return alerts

