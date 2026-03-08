from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from config.settings import Settings
from utils.helpers import new_alert_id, parse_timestamp, utc_now_iso


RULE_NAME = "Brute Force Login Attempts"
SEVERITY = "High"


def detect(events: list[dict[str, Any]], settings: Settings) -> list[dict[str, Any]]:
    """Detect repeated failed logins for the same username + source IP in a time window."""
    window = timedelta(minutes=settings.BRUTE_FORCE_WINDOW_MINUTES)
    threshold = settings.BRUTE_FORCE_FAIL_THRESHOLD

    # Group login failures by (user, source_ip) then sliding-window count.
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if (e.get("event_type") or "").lower() not in {"login", "authentication", "auth"}:
            continue
        if (e.get("status") or "").lower() not in {"failed", "failure", "invalid", "denied"}:
            continue
        user = (e.get("username") or "").strip()
        ip = (e.get("source_ip") or "").strip()
        if not user or not ip:
            continue
        buckets[(user, ip)].append(e)

    alerts: list[dict[str, Any]] = []
    for (user, ip), records in buckets.items():
        # Sort by timestamp; discard records without parseable timestamps.
        parsed: list[tuple] = []
        for r in records:
            dt = parse_timestamp(r.get("timestamp"))
            if dt:
                parsed.append((dt, r))
        parsed.sort(key=lambda x: x[0])

        q: deque[tuple] = deque()
        for dt, r in parsed:
            q.append((dt, r))
            while q and (dt - q[0][0]) > window:
                q.popleft()
            if len(q) >= threshold:
                # Build one alert per burst; include last N event_ids for evidence.
                evidence_events = list(q)
                event_ids = [ev.get("event_id", "") for _, ev in evidence_events if ev.get("event_id")]
                first_ts = evidence_events[0][0].isoformat()
                last_ts = evidence_events[-1][0].isoformat()

                alerts.append(
                    {
                        "alert_id": new_alert_id(),
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "created_at": utc_now_iso(),
                        "event_timestamp": last_ts,
                        "username": user,
                        "source_ip": ip,
                        "hostname": (evidence_events[-1][1].get("hostname") or ""),
                        "description": (
                            f"Detected {len(q)} failed login attempts for user '{user}' from {ip} "
                            f"within {settings.BRUTE_FORCE_WINDOW_MINUTES} minutes "
                            f"({first_ts} → {last_ts})."
                        ),
                        "evidence": {
                            "failed_attempt_count": len(q),
                            "window_minutes": settings.BRUTE_FORCE_WINDOW_MINUTES,
                            "first_seen": first_ts,
                            "last_seen": last_ts,
                            "sample_event_ids": event_ids[-10:],
                        },
                        "related_event_ids": event_ids,
                    }
                )

                # Reset queue after alert so we don't emit spam for every subsequent event.
                q.clear()

    return alerts

