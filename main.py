from ingestion.loader import load_logs
from ingestion.normalizer import normalize_logs
from detections.engine import run_detections
from detections.rule_loader import load_rules
from detections.rule_engine import run_yaml_rules
from reporting.alert_writer import write_alerts_to_json
from reporting.summary_report import generate_summary, print_summary


def main():
    raw_logs = load_logs("data/sample_logs.json")
    normalized_logs = normalize_logs(raw_logs)

    python_alerts = run_detections(normalized_logs)

    yaml_rules = load_rules("rules")
    yaml_alerts = run_yaml_rules(normalized_logs, yaml_rules)

    all_alerts = python_alerts + yaml_alerts

    write_alerts_to_json(all_alerts, "alerts_output.json")

    summary = generate_summary(all_alerts)
    print_summary(summary)

    print("\nAlerts written to alerts_output.json")


if __name__ == "__main__":
    main()
