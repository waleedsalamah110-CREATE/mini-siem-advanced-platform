# Mini SIEM Detection Platform

A **portfolio-grade, local Python mini-SIEM** that simulates a junior detection engineering workflow:
**log ingestion → normalization → rule-based detections → MITRE ATT&CK mapping → structured alert output → SOC-style reporting**.

This project is intentionally lightweight (no web app, no Flask/Django) and is designed to be easy to demo in interviews:

- Detection logic is modular and readable
- Outputs look like SOC triage artifacts (JSON alerts + terminal summary)
- Raw logs are preserved for investigation pivots

---

## Overview

`mini-siem-detection-platform` ingests JSON logs from `data/sample_logs.json`, normalizes them into a **common event schema**, executes several **rule-based detections**, enriches alerts with **MITRE ATT&CK** metadata, writes the results to `alerts_output.json`, and prints a **SOC-style detection summary**.

---

## Features

- **Log ingestion** from JSON with safe parsing
- **Normalization** to a common event schema with investigator-friendly pivots
- **Detection engine** running multiple rules
- **MITRE ATT&CK mapping** per rule
- **Structured JSON alerts** for downstream workflows
- **SOC-style terminal report** (totals, severities, affected entities, per-rule counts)

---

## Architecture / Project Structure

```
mini-siem-detection-platform/
├── main.py
├── requirements.txt
├── README.md
├── alerts_output.json
├── config/
│   ├── __init__.py
│   └── settings.py
├── data/
│   └── sample_logs.json
├── ingestion/
│   ├── __init__.py
│   ├── loader.py
│   └── normalizer.py
├── detections/
│   ├── __init__.py
│   ├── brute_force.py
│   ├── suspicious_powershell.py
│   ├── privilege_escalation.py
│   ├── impossible_travel.py
│   └── engine.py
├── mappings/
│   ├── __init__.py
│   └── mitre_attack.py
├── reporting/
│   ├── __init__.py
│   ├── alert_writer.py
│   └── summary_report.py
└── utils/
    ├── __init__.py
    └── helpers.py
```

---

## Detection Rules

### 1) Brute Force Login Attempts (High)
- **Goal**: Detect repeated authentication failures suggesting password guessing
- **Logic**: \( \ge 5 \) failed logins within **10 minutes** for the same **username + source IP**
- **SOC value**: quickly identifies targeted accounts and attacking IPs

### 2) Suspicious PowerShell Execution (High)
- **Goal**: Flag suspicious PowerShell usage commonly associated with initial access / execution chains
- **Logic**: PowerShell process execution where the command line contains indicators like:
  - `EncodedCommand`
  - `Invoke-Expression`
  - `DownloadString`
  - `IEX`
  - `FromBase64String`

### 3) Privilege Escalation / Admin Change (Critical)
- **Goal**: Identify privilege elevation (e.g., admin group membership changes)
- **Logic**: Match admin/privilege indicators such as:
  - “added to Local Administrators”
  - “elevated privileges”
  - other privilege-related markers

### 4) Impossible Travel (Valid Accounts) (High)
- **Goal**: Catch compromised credentials used from geographically distant locations
- **Logic**: Same user successfully authenticates from different locations within **30 minutes**
  and the implied speed exceeds a configurable threshold.

---

## MITRE ATT&CK Mapping

| Rule | Tactic | Technique |
|---|---|---|
| Brute Force Login Attempts | Credential Access | T1110 Brute Force |
| Suspicious PowerShell Execution | Execution | T1059.001 PowerShell |
| Privilege Escalation / Admin Change | Privilege Escalation | T1068 Exploitation for Privilege Escalation |
| Impossible Travel (Valid Accounts) | Defense Evasion / Persistence (context: Valid Accounts) | T1078 Valid Accounts |

---

## Example Output

When you run `python main.py`, you’ll see a SOC-style summary:

```
========================================================================
MINI SIEM DETECTION SUMMARY
========================================================================
Raw logs ingested:         13
Events normalized:         13
Total alerts:              5

SEVERITY COUNTS
------------------------------------------------------------------------
Critical:                  1
High:                      4

DETECTION BREAKDOWN (by rule)
------------------------------------------------------------------------
Privilege Escalation / Admin Change:     1 (Critical:1)
Suspicious PowerShell Execution:         2 (High:2)
Brute Force Login Attempts:              1 (High:1)
Impossible Travel (Valid Accounts):      1 (High:1)

AFFECTED ENTITIES
------------------------------------------------------------------------
Affected users:            a.chan, j.smith, svc.backup
Affected source IPs:       10.10.20.55, 192.168.10.25, 203.0.113.50, 203.0.113.99

Alerts written to:         .../alerts_output.json
========================================================================
```

Alerts are also written as structured JSON to `alerts_output.json` (suitable for piping into other tools later).

---

## How to Run

From the project root:

```bash
pip install -r requirements.txt
python main.py
```

---

## Why This Project Matters (SOC / Detection Engineering)

This project demonstrates practical detection engineering fundamentals that come up in SOC and detection roles:

- **Normalization** (turn messy logs into consistent pivots)
- **Rule design** with realistic thresholds and evidence
- **Alert structure** (fields that help triage quickly)
- **MITRE ATT&CK mapping** (communicating attacker behavior)
- **Reporting** (useful summaries for analysts and stakeholders)

It’s intentionally designed to be interview-friendly: you can walk through the pipeline, explain each detection’s logic, discuss tuning/false positives, and propose next steps.

---

## Future Improvements

- Sigma-like rule format (YAML) and a generic rule loader
- YAML/JSON configuration for thresholds and keyword lists
- More log sources (Linux auth, Okta/Azure AD exports, EDR telemetry, DNS/proxy)
- Unit tests (pytest) and synthetic log generators
- Docker packaging for consistent demo runs
- Alert deduplication/correlation (cases, incident grouping)
- Baselines / allowlists to reduce false positives

