from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the mini SIEM platform.

    Keep these simple and recruiter-readable — this is meant to feel like an
    internal SOC utility with sensible defaults.
    """

    PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

    # Paths
    SAMPLE_LOG_PATH: Path = PROJECT_ROOT / "data" / "sample_logs.json"
    ALERTS_OUTPUT_PATH: Path = PROJECT_ROOT / "alerts_output.json"

    # Brute force thresholds
    BRUTE_FORCE_FAIL_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_MINUTES: int = 10

    # Impossible travel thresholds
    IMPOSSIBLE_TRAVEL_WINDOW_MINUTES: int = 30
    IMPOSSIBLE_TRAVEL_SPEED_KMPH: int = 900  # ~commercial jet cruise; above is suspicious

    # Reporting
    TOP_N_LISTS: int = 10
