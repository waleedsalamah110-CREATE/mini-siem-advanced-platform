from __future__ import annotations

from typing import Any

from config.settings import Settings
from utils.helpers import contains_any_case_insensitive, new_alert_id, utc_now_iso


RULE_NAME = "Privilege Escalation / Admin Change"
SEVERITY = "Critical"

PRIV_ESC_KEYWORDS = [
    "added to administrators",
    "added to local administrators",
    "added to admin group",
    "local admin",
    "elevated privileges",
    "privilege escalation",
    "seDebugPrivilege",
    "seTcbPrivilege",
]


def detect(events: list[dict[str, Any]], settings: Settings) -> list[dict[str, Any]]:
    _ = settings  # reserved for future tuning

    alerts: list[dict[str, Any]] = []
    for e in events:
        etype = (e.get("event_type") or "").lower()
        change = e.get("privilege_change") or ""
        raw_message = (e.get("raw_log") or {}).get("message") or ""

        # Privilege events are often noisy; constrain by common event types where possible.
        candidate = etype in {"privilege_change", "group_membership_change", "account_change", "security_change"}
        text = f"{change} {raw_message}".strip()
        if not text:
            continue

        if not candidate and not contains_any_case_insensitive(text, PRIV_ESC_KEYWORDS):
            continue

        if not contains_any_case_insensitive(text, PRIV_ESC_KEYWORDS):
            continue

        user = (e.get("username") or "").strip()
        ip = (e.get("source_ip") or "").strip()
        host = (e.get("hostname") or "").strip()

        alerts.append(
            {
                "alert_id": new_alert_id(),
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "created_at": utc_now_iso(),
                "event_timestamp": e.get("timestamp") or "",
                "username": user,
                "source_ip": ip,
                "hostname": host,
                "description": "Detected a privilege escalation / admin group membership change indicator.",
                "evidence": {
                    "event_type": e.get("event_type") or "",
                    "privilege_change": e.get("privilege_change") or "",
                    "raw_message": raw_message,
                    "event_id": e.get("event_id") or "",
                    "log_source": e.get("log_source") or "",
                },
                "related_event_ids": [e.get("event_id")] if e.get("event_id") else [],
            }
        )

    return alerts

