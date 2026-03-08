from __future__ import annotations

import json
import sys
from pathlib import Path

from config.settings import Settings
from detections.engine import run_all_detections
from ingestion.loader import load_json_logs
from ingestion.normalizer import normalize_logs
from reporting.alert_writer import write_alerts_json
from reporting.summary_report import print_summary_report


def main() -> int:
    settings = Settings()

    raw_logs = load_json_logs(settings.SAMPLE_LOG_PATH)
    events = normalize_logs(raw_logs)

    alerts = run_all_detections(
        events=events,
        settings=settings,
    )

    write_alerts_json(alerts, settings.ALERTS_OUTPUT_PATH)

    print_summary_report(
        alerts=alerts,
        settings=settings,
        total_events=len(events),
        total_raw_logs=len(raw_logs),
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        raise
