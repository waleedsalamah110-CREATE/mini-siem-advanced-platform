from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from utils.helpers import as_list


class LogLoadError(RuntimeError):
    pass


def load_json_logs(path: Path) -> list[dict[str, Any]]:
    """Load raw logs from a JSON file.

    Expected format: a JSON array of objects (each object is a raw log record).
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise LogLoadError(f"Failed to read log file: {path} ({e})") from e

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise LogLoadError(f"Invalid JSON in log file: {path} ({e})") from e

    items = as_list(parsed)
    logs: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if isinstance(item, dict):
            logs.append(item)
        else:
            # Skip invalid records rather than failing the pipeline.
            continue

    return logs

