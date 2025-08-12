# SOC Copilot — Wazuh Edition

An **AI-driven Security Operations Center (SOC) automation framework** that integrates Wazuh telemetry with MITRE ATT&CK mapping, transparent risk scoring, automated playbook retrieval, incident ticket drafting, sensor health analysis, and SOC analyst Q&A — delivering a complete, end-to-end triage workflow.

---

## 📌 Overview

**SOC Copilot — Wazuh Edition** is a **portfolio-grade cybersecurity automation system** designed to replicate and enhance the analytical workflows of modern SOC environments.  
It empowers **Tier-1 and Tier-2 SOC analysts** to rapidly ingest, analyze, and act upon security alerts, significantly reducing manual triage effort.

This implementation is built in **Python** and leverages **AI-assisted engineering** to achieve deterministic, reproducible results.

The repository includes **synthetic (non-production) data** for demonstration purposes, ensuring there is no exposure of proprietary or sensitive information.  

The architecture, however, is fully capable of operating with **real-world telemetry** in production SOC environments, with only minor configuration changes required to integrate with live data pipelines.

---

## 🧠 Why Use Synthetic Data

- **Security and Privacy**: Protects against accidental leakage of sensitive or proprietary incident details.  
- **Repeatable Demonstrations**: Synthetic datasets ensure consistent outputs for demos, documentation, and testing.  
- **Adaptability**: All processing logic is agnostic to whether input data is synthetic or live, meaning production deployment requires only pointing the ingestion service at the desired telemetry source.

---

## 🚀 Key Features

- **Multi-Source Telemetry Normalization**  
  Ingests alerts from **Wazuh** (primary), Zeek, AWS CloudTrail, and other supported sources, transforming them into a unified schema.

- **MITRE ATT&CK Technique Mapping**  
  Automatically maps observable indicators to tactics and techniques (e.g., `T1059.003 – PowerShell`) with confidence scores and concise justifications.

- **Deterministic Risk Scoring**  
  Employs a transparent, fixed-weight scoring model considering base severity, asset criticality, technique risk, and spread indicators — with escalation rules for critical contexts.

- **Contextual Playbook Retrieval**  
  Matches mapped techniques and tags to relevant containment and eradication procedures.

- **Automated Incident Ticket Drafting**  
  Produces fully formatted Jira or ServiceNow tickets with MITRE mappings, IOC summaries, key evidence, recommended actions, and playbook references.

- **Sensor Health & Coverage Insights**  
  Reports endpoint coverage metrics by organizational unit (OU) or VPC and identifies blind spots.

- **Structured, Analyst-Ready Output**  
  Generates a consolidated JSON containing normalized alerts, triage results, incident summaries, sensor health metrics, and prioritized rankings.

---

## 🛠 Architecture

```text
[Telemetry Sources: Wazuh / Zeek / AWS CloudTrail]
        │
        ▼
[Ingest Service] → Normalize → Enrich from asset inventory
        │
        ▼
[MITRE Mapping] → Map observables to tactics/techniques
        │
        ▼
[Risk Scoring] → Apply deterministic formula + escalation
        │
        ▼
[Playbook Retrieval] → Match by technique and tags
        │
        ▼
[Ticket Drafting] → Jira/ServiceNow formats
        │
        ▼
[Output] → JSON with triage, rankings, sensor health, and summaries
```
## Repository Structure

SOC-Copilot-Wazuh-version/
├── app/
│   ├── api/                 # API endpoints (FastAPI)
│   ├── models/              # Pydantic schemas
│   └── services/            # Ingest, scoring, MITRE mapping logic
├── data/
│   └── samples/             # Synthetic telemetry and AI-generated outputs
├── tests/                   # Unit tests
├── tools/                   # Demo scripts
├── ui/                      # Streamlit/Flask-based user interface
├── requirements.txt         # Python dependencies
└── README.md

---

## Setup Instructions

### 1. Clone the Repository
```
git clone https://github.com/gtaxay/SOC-Copilot-Wazuh-version.git
cd SOC-Copilot-Wazuh-version
```
### 2. Create and Activate a Virtual Environment
Mac/Linux:
```
  python3 -m venv venv
  source venv/bin/activate
```
Windows (PowerShell):
```
  python -m venv venv
  venv\Scripts\Activate.ps1
```
### 3. Install Dependencies
```
  pip install -r requirements.txt
```
### 4. Run the UI
```
  python ui/app.py
```
### 5. Run the Demo Pipeline
```
  bash tools/demo.sh
```

---

## 📊 Sample Output

A complete demonstration output can be found in:
```
  data/samples/llm_output.json
```

This file includes:
- Normalized alerts
- MITRE ATT&CK mappings
- Risk scores and rationale
- Playbook recommendations
- Incident summaries
- Ticket drafts
- Sensor health coverage
- Risk-based rankings

---

## Demo / Example
This example demonstrates how SOC Copilot processes a synthetic Wazuh alert from ingestion through to ticket drafting.

### Sample Input

```json
[
  {
    "alert_id": "wz-8842",
    "source": "wazuh",
    "vendor": "Wazuh",
    "timestamp": "2025-08-10T12:03:21Z",
    "rule": {"level": 7, "description": "Windows command execution"},
    "agent": {"id":"001","name":"FIN-LAP-22","ip":"10.10.12.34"},
    "data": {"win": {"eventdata": {
      "CommandLine": "powershell.exe -enc SQBt...",
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "User": "CORP\\jdoe",
      "DestinationIp": "203.0.113.45",
      "Hashes": "MD5=...,SHA1=...,SHA256=abc123..."
    }, "system": {"computer": "FIN-LAP-22"}}}
  }
]
```

### Output

```json

{"normalized_alerts":[{"alert_id":"wz-8842","source":"wazuh","vendor":"Wazuh","timestamp":"2025-08-10T12:03:21Z","asset":{"hostname":"FIN-LAP-22","instance_id":null,"ip":"10.10.12.34","ou_or_vpc":"Finance-Endpoints","criticality":8,"owner":"CORP\\jdoe"},"actor":{"user":"CORP\\jdoe","process":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","pid":null},"observables":{"hashes":["abc123..."],"domains":[],"ips":["203.0.113.45"],"paths":[],"commands":["powershell.exe -enc SQBt..."],"detections":["Windows command execution"]},"base_severity":7,"raw":{"alert_id":"wz-8842","source":"wazuh","vendor":"Wazuh","timestamp":"2025-08-10T12:03:21Z","rule":{"level":7,"description":"Windows command execution"},"agent":{"id":"001","name":"FIN-LAP-22","ip":"10.10.12.34"},"data":{"win":{"eventdata":{"CommandLine":"powershell.exe -enc SQBt...","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","User":"CORP\\jdoe","DestinationIp":"203.0.113.45","Hashes":"MD5=...,SHA1=...,SHA256=abc123..."},"system":{"computer":"FIN-LAP-22"}}}}}],"triage":[{"alert_id":"wz-8842","mitre_mapping":[{"tactic":"TA0002_Execution","technique":"T1059.003_PowerShell","confidence":0.85,"rationale":"Encoded/interactive PowerShell observed in endpoint telemetry."},{"tactic":"TA0011_Command and Control","technique":"T1105_Ingress Tool Transfer","confidence":0.5,"rationale":"External IP contact during suspicious execution."}],"risk_score":{"value":6.4,"drivers":["base","criticality","technique","spread"],"rationale":"Base=7, Crit=8, Tech=6, Spread=0"},"playbook_recommendations":[{"playbook_id":"pb-powershell-lolbin","title":"Containment for Malicious PowerShell","excerpt":"1) Isolate host; 2) Kill process; 3) Collect PS logs; 4) Block IOC..."}],"incident_summary":{"who":"CORP\\jdoe on FIN-LAP-22","what":"powershell.exe -enc SQBt...","when":"2025-08-10T12:03:21Z","where":"Finance-Endpoints","impact":"Potential security incident on monitored asset","severity_rank":"1"},"ticket_draft":{"system":"servicenow","title":"[Medium] Incident on FIN-LAP-22","severity":"Medium","classification":"Execution / Possible C2","mapped_mitre":["T1059.003","T1105"],"evidence":{"ioc_summary":{"ips":["203.0.113.45"],"domains":[],"hashes":["abc123..."],"paths":[]},"key_events":["2025-08-10T12:03:21Z :: powershell.exe -enc SQBt..."]},"recommended_actions":["Isolate host","Terminate malicious processes","Collect logs","Block IOCs"],"owner_suggestion":null,"references":["pb-powershell-lolbin"]}}],"sensor_health":null,"qa":{"query":null,"query_plan":null,"result_set":[],"answer":null},"ranking":[{"alert_id":"wz-8842","risk_score":6.4,"priority":1}],"errors":[]}
```



## Schema Reference
### Normalized Alert Schema

```json
{
  "alert_id": "string",
  "source": "wazuh|zeek|cloudtrail|other",
  "vendor": "string",
  "timestamp": "ISO8601",
  "asset": {
    "hostname": "string|null",
    "instance_id": "string|null",
    "ip": "string|null",
    "ou_or_vpc": "string|null",
    "criticality": 1-10|null,
    "owner": "string|null"
  },
  "actor": {
    "user": "string|null",
    "process": "string|null",
    "pid": "integer|null"
  },
  "observables": {
    "hashes": ["sha256"...],
    "domains": ["string"...],
    "ips": ["string"...],
    "paths": ["string"...],
    "commands": ["string"...],
    "detections": ["string"...]
  },
  "base_severity": 1-10,
  "raw": {}
}
```
---

### Risk Scoring Formula

```markdown
risk_score = (0.4 × base_severity)
           + (0.3 × criticality)
           + (0.2 × technique_risk)
           + (0.1 × spread_indicator)
```
#### Escalation Triggers:
- Domain Controller or Tier-0 assets
- Asset criticality ≥ 9
- Ransomware indicators (T1486)
- Sensor inactive within the last 24 hours

---
  





