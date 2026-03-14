import json


def write_alerts_to_json(alerts, output_file="alerts_output.json"):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4)
