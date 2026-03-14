from collections import Counter

def generate_summary(alerts):
    summary = {
        "total_alerts": len(alerts),
        "severity_counts": {},
        "affected_users": {},
        "affected_ips": {}
    }

    sev = Counter()
    users = Counter()
    ips = Counter()

    for alert in alerts:
        sev[alert.get("severity", "Unknown")] += 1

        if alert.get("username"):
            users[alert.get("username")] += 1

        if alert.get("source_ip"):
            ips[alert.get("source_ip")] += 1

    summary["severity_counts"] = dict(sev)
    summary["affected_users"] = dict(users)
    summary["affected_ips"] = dict(ips)

    return summary


def print_summary(summary):
    print("\n=== SOC Detection Summary ===")
    print(f"Total Alerts: {summary['total_alerts']}")

    print("\nSeverity:")
    for k, v in summary["severity_counts"].items():
        print(f"{k}: {v}")

    print("\nUsers:")
    for k, v in summary["affected_users"].items():
        print(f"{k}: {v}")

    print("\nIPs:")
    for k, v in summary["affected_ips"].items():
        print(f"{k}: {v}")
