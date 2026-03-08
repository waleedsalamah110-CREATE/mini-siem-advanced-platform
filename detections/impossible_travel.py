from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any, Optional

from config.settings import Settings
from utils.helpers import haversine_km, new_alert_id, parse_timestamp, utc_now_iso


RULE_NAME = "Impossible Travel (Valid Accounts)"
SEVERITY = "High"


# A small geo lookup table for demo purposes (expandable).
LOCATION_GEO: dict[str, tuple[float, float]] = {
    "Melbourne, AU": (-37.8136, 144.9631),
    "Sydney, AU": (-33.8688, 151.2093),
    "Dubai, AE": (25.2048, 55.2708),
    "London, GB": (51.5072, -0.1276),
    "New York, US": (40.7128, -74.0060),
    "Singapore, SG": (1.3521, 103.8198),
}


def _coords(location: str) -> Optional[tuple[float, float]]:
    return LOCATION_GEO.get(location)


def detect(events: list[dict[str, Any]], settings: Settings) -> list[dict[str, Any]]:
    """Detect successful logins from distant locations within an impossible timeframe."""
    window = timedelta(minutes=settings.IMPOSSIBLE_TRAVEL_WINDOW_MINUTES)

    # Consider only successful auth events with a username + location + timestamp.
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if (e.get("event_type") or "").lower() not in {"login", "authentication", "auth"}:
            continue
        if (e.get("status") or "").lower() not in {"success", "successful", "ok"}:
            continue
        user = (e.get("username") or "").strip()
        if not user:
            continue
        if not (e.get("location") or "").strip():
            continue
        if not parse_timestamp(e.get("timestamp")):
            continue
        by_user[user].append(e)

    alerts: list[dict[str, Any]] = []
    for user, records in by_user.items():
        records = sorted(records, key=lambda r: parse_timestamp(r.get("timestamp")) or 0)

        for i in range(len(records) - 1):
            a = records[i]
            b = records[i + 1]
            dta = parse_timestamp(a.get("timestamp"))
            dtb = parse_timestamp(b.get("timestamp"))
            if not dta or not dtb:
                continue
            if (dtb - dta) <= timedelta(seconds=0):
                continue
            if (dtb - dta) > window:
                continue

            loc_a = (a.get("location") or "").strip()
            loc_b = (b.get("location") or "").strip()
            if not loc_a or not loc_b or loc_a == loc_b:
                continue

            ca = _coords(loc_a)
            cb = _coords(loc_b)
            if not ca or not cb:
                continue

            distance_km = haversine_km(ca[0], ca[1], cb[0], cb[1])
            hours = (dtb - dta).total_seconds() / 3600.0
            speed_kmph = distance_km / hours if hours > 0 else float("inf")

            if speed_kmph < settings.IMPOSSIBLE_TRAVEL_SPEED_KMPH:
                continue

            alerts.append(
                {
                    "alert_id": new_alert_id(),
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "created_at": utc_now_iso(),
                    "event_timestamp": dtb.isoformat(),
                    "username": user,
                    "source_ip": (b.get("source_ip") or "").strip(),
                    "hostname": (b.get("hostname") or "").strip(),
                    "description": (
                        f"User '{user}' authenticated from '{loc_a}' then '{loc_b}' within "
                        f"{int((dtb - dta).total_seconds() // 60)} minutes "
                        f"({distance_km:.0f} km at ~{speed_kmph:.0f} km/h)."
                    ),
                    "evidence": {
                        "first_login": {
                            "timestamp": dta.isoformat(),
                            "location": loc_a,
                            "source_ip": (a.get("source_ip") or "").strip(),
                            "hostname": (a.get("hostname") or "").strip(),
                            "event_id": a.get("event_id") or "",
                        },
                        "second_login": {
                            "timestamp": dtb.isoformat(),
                            "location": loc_b,
                            "source_ip": (b.get("source_ip") or "").strip(),
                            "hostname": (b.get("hostname") or "").strip(),
                            "event_id": b.get("event_id") or "",
                        },
                        "distance_km": round(distance_km, 2),
                        "minutes_between": int((dtb - dta).total_seconds() // 60),
                        "estimated_speed_kmph": round(speed_kmph, 2),
                        "threshold_speed_kmph": settings.IMPOSSIBLE_TRAVEL_SPEED_KMPH,
                        "window_minutes": settings.IMPOSSIBLE_TRAVEL_WINDOW_MINUTES,
                    },
                    "related_event_ids": [
                        a.get("event_id") if a.get("event_id") else "",
                        b.get("event_id") if b.get("event_id") else "",
                    ],
                }
            )

    return alerts

