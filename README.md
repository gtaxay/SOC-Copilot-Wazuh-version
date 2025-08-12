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

###1. Clone the Repository
git clone https://github.com/gtaxay/SOC-Copilot-Wazuh-version.git
cd SOC-Copilot-Wazuh-version

###2. Create and Activate a Virtual Environment
Mac/Linux:

  python3 -m venv venv
  source venv/bin/activate

Windows (PowerShell):

  python -m venv venv
  venv\Scripts\Activate.ps1

###3. Install Dependencies

  pip install -r requirements.txt
  
###4. Run the UI

  python ui/app.py

###5. Run the Demo Pipeline

  bash tools/demo.sh

---


