from __future__ import annotations

import json
import math
import re
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_alert_id() -> str:
    return str(uuid.uuid4())


def safe_json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse common timestamp formats into an aware UTC datetime.

    Accepts ISO-8601 strings and epoch seconds (int/float).
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OSError, ValueError):
            return None

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None

        # Handle trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            return None

    return None


def isoformat_or_empty(dt: Optional[datetime]) -> str:
    return dt.isoformat() if dt else ""


def normalize_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def contains_any_case_insensitive(haystack: str, needles: Iterable[str]) -> bool:
    h = haystack.lower()
    return any(n.lower() in h for n in needles)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points (km)."""
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)

    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


def as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []

