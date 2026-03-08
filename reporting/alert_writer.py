from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_alerts_json(alerts: list[dict[str, Any]], path: Path) -> None:
    """Write structured alerts to disk (JSON array)."""
    payload = {
        "alerts": alerts,
        "alert_count": len(alerts),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

