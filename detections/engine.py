from detections import brute_force, suspicious_powershell, privilege_escalation, impossible_travel


def run_detections(events):
    alerts = []

    for module in [brute_force, suspicious_powershell, privilege_escalation, impossible_travel]:
        if hasattr(module, "detect"):
            try:
                alerts.extend(module.detect(events))
            except TypeError:
                # Some modules may expect a settings argument
                try:
                    from config.settings import Settings
                    alerts.extend(module.detect(events, Settings()))
                except Exception as e:
                    print(f"Skipping {module.__name__}: {e}")

    return alerts

