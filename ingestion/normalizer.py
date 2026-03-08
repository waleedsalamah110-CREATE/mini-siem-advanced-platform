from __future__ import annotations

from typing import Any

from utils.helpers import as_dict, as_str, normalize_whitespace, parse_timestamp


def _pick_first(d: dict[str, Any], keys: list[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def normalize_log(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize heterogeneous raw logs into a common event schema.

    This intentionally stays *schema-light*: we keep fields SOCs commonly pivot on,
    and preserve the original record in `raw_log` for investigation.
    """
    src = as_str(raw.get("source") or raw.get("log_source") or raw.get("provider"))
    event_id = as_str(raw.get("event_id") or raw.get("id") or raw.get("record_id"))

    ts = _pick_first(raw, ["timestamp", "time", "@timestamp", "event_time", "utc_time"])
    dt = parse_timestamp(ts)
    timestamp = dt.isoformat() if dt else as_str(ts)

    event_type = as_str(
        raw.get("event_type")
        or raw.get("type")
        or raw.get("action")
        or raw.get("event_action")
        or raw.get("event_name")
    )

    username = as_str(_pick_first(raw, ["username", "user", "account", "user_name", "target_user"]))
    source_ip = as_str(_pick_first(raw, ["source_ip", "src_ip", "ip", "client_ip"]))
    hostname = as_str(_pick_first(raw, ["hostname", "host", "computer_name", "device_name"]))

    process_name = as_str(_pick_first(raw, ["process_name", "image", "process", "exe"]))
    command_line = as_str(_pick_first(raw, ["command_line", "cmdline", "command", "process_command_line"]))
    command_line = normalize_whitespace(command_line) if command_line else ""

    location = as_str(_pick_first(raw, ["location", "geo", "geo_city", "city"]))
    privilege_change = as_str(_pick_first(raw, ["privilege_change", "change", "group_change", "activity"]))
    status = as_str(_pick_first(raw, ["status", "result", "outcome"]))

    normalized = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "hostname": hostname,
        "process_name": process_name,
        "command_line": command_line,
        "location": location,
        "privilege_change": privilege_change,
        "status": status,
        "log_source": src,
        "raw_log": raw,
    }

    # Ensure the "raw_log" is always a dict (avoid surprises downstream).
    normalized["raw_log"] = as_dict(normalized["raw_log"])
    return normalized


def normalize_logs(raw_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_log(r) for r in raw_logs]

