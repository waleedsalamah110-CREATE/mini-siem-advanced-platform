def match_rule(event, rule):
    if not isinstance(rule, dict):
        return False

    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        return False

    for field, value in detection.items():
        if str(event.get(field, "")).lower() != str(value).lower():
            return False

    return True


def run_yaml_rules(events, rules):
    alerts = []

    for event in events:
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            if match_rule(event, rule):
                alerts.append({
                    "title": rule.get("title"),
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("title"),
                    "severity": rule.get("level", "medium").title(),
                    "status": "New",
                    "description": rule.get("description"),
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "hostname": event.get("hostname"),
                    "first_seen": event.get("timestamp"),
                    "last_seen": event.get("timestamp"),
                    "event_count": 1,
                    "mitre_tactic": rule.get("mitre_tactic"),
                    "mitre_technique_id": rule.get("mitre_technique_id"),
                    "mitre_technique_name": rule.get("mitre_technique_name"),
                    "triage_notes": f"Investigate event matched by rule: {rule.get('title')}",
                    "recommended_actions": [
                        "Review related logs",
                        "Validate user activity",
                        "Determine whether containment is required"
                    ]
                })

    return alerts
    