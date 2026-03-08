from __future__ import annotations

from typing import Any

from config.settings import Settings
from utils.helpers import contains_any_case_insensitive, new_alert_id, utc_now_iso


RULE_NAME = "Suspicious PowerShell Execution"
SEVERITY = "High"

SUSPICIOUS_KEYWORDS = [
    "EncodedCommand",
    "Invoke-Expression",
    "DownloadString",
    "IEX",
    "FromBase64String",
]


def detect(events: list[dict[str, Any]], settings: Settings) -> list[dict[str, Any]]:
    _ = settings  # reserved for future tuning

    alerts: list[dict[str, Any]] = []
    for e in events:
        pname = (e.get("process_name") or "").lower()
        cmd = e.get("command_line") or ""
        if not cmd:
            continue

        # We treat powershell* processes as the primary signal, but also allow cmdline hits
        # even if the process_name is missing (common in partial logs).
        is_ps = "powershell" in pname or "pwsh" in pname or "powershell" in cmd.lower()
        if not is_ps:
            continue

        if not contains_any_case_insensitive(cmd, SUSPICIOUS_KEYWORDS):
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
                "description": (
                    "PowerShell execution contained suspicious indicators ("
                    + ", ".join([k for k in SUSPICIOUS_KEYWORDS if k.lower() in cmd.lower()])
                    + ")."
                ),
                "evidence": {
                    "process_name": e.get("process_name") or "",
                    "command_line": cmd,
                    "matched_keywords": [k for k in SUSPICIOUS_KEYWORDS if k.lower() in cmd.lower()],
                    "event_id": e.get("event_id") or "",
                    "log_source": e.get("log_source") or "",
                },
                "related_event_ids": [e.get("event_id")] if e.get("event_id") else [],
            }
        )

    return alerts

