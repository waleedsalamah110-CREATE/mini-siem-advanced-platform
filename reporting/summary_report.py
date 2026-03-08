from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from config.settings import Settings


def _fmt_kv(label: str, value: str, width: int = 24) -> str:
    return f"{label:<{width}} {value}"


def _fmt_list(items: list[str], max_items: int) -> str:
    if not items:
        return "-"
    if len(items) <= max_items:
        return ", ".join(items)
    return ", ".join(items[:max_items]) + f" (+{len(items) - max_items} more)"


def print_summary_report(
    alerts: list[dict[str, Any]],
    settings: Settings,
    *,
    total_events: int,
    total_raw_logs: int,
) -> None:
    severity_counts = Counter(a.get("severity", "Unknown") for a in alerts)
    rule_counts = Counter(a.get("rule_name", "Unknown") for a in alerts)

    users = sorted({(a.get("username") or "").strip() for a in alerts if (a.get("username") or "").strip()})
    ips = sorted({(a.get("source_ip") or "").strip() for a in alerts if (a.get("source_ip") or "").strip()})

    # Rule → severity breakdown (useful for "SOC triage" feel)
    per_rule_sev: dict[str, Counter[str]] = defaultdict(Counter)
    for a in alerts:
        per_rule_sev[a.get("rule_name", "Unknown")][a.get("severity", "Unknown")] += 1

    line = "=" * 72
    print(line)
    print("MINI SIEM DETECTION SUMMARY")
    print(line)

    print(_fmt_kv("Raw logs ingested:", str(total_raw_logs)))
    print(_fmt_kv("Events normalized:", str(total_events)))
    print(_fmt_kv("Total alerts:", str(len(alerts))))
    print()

    print("SEVERITY COUNTS")
    print("-" * 72)
    for sev in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]:
        if sev in severity_counts:
            print(_fmt_kv(f"{sev}:", str(severity_counts[sev])))
    print()

    print("DETECTION BREAKDOWN (by rule)")
    print("-" * 72)
    for rule, count in rule_counts.most_common():
        sev_detail = ", ".join(f"{s}:{c}" for s, c in per_rule_sev[rule].most_common())
        print(_fmt_kv(rule + ":", f"{count} ({sev_detail})", width=44))
    print()

    print("AFFECTED ENTITIES")
    print("-" * 72)
    print(_fmt_kv("Affected users:", _fmt_list(users, settings.TOP_N_LISTS)))
    print(_fmt_kv("Affected source IPs:", _fmt_list(ips, settings.TOP_N_LISTS)))
    print()

    print(_fmt_kv("Alerts written to:", str(settings.ALERTS_OUTPUT_PATH)))
    print(line)

