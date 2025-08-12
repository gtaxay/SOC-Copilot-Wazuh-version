# SOC Copilot — Wazuh Version

**AI-powered SOC automation** that ingests Wazuh telemetry, normalizes and enriches alerts, maps to MITRE ATT&CK, calculates transparent risk scores, retrieves playbooks, drafts tickets, evaluates sensor health, and supports SOC analyst Q&A — all through a single automated pipeline.

---

## 📌 Overview

This project is a **portfolio-grade, AI-assisted SOC Copilot** that demonstrates real-world integration of:
- **Security telemetry ingestion** (Wazuh, Zeek, AWS CloudTrail)
- **Data normalization & enrichment**
- **MITRE ATT&CK mapping**
- **Deterministic risk scoring**
- **Automated playbook retrieval**
- **Incident ticket drafting (Jira/ServiceNow)**
- **Sensor health evaluation**
- **Natural language Q&A over incidents**

Built with **Python** and leveraging **AI prompting techniques** to generate the core logic and schemas, this project mirrors workflows used in modern SOCs, enabling Tier-1 and Tier-2 analysts to reduce manual triage time.

---

## 🚀 Features

- **Unified Telemetry Normalization**  
  Converts raw Wazuh JSON alerts into a consistent schema for cross-source analysis.

- **MITRE ATT&CK Mapping**  
  Uses observable indicators to infer tactics/techniques with confidence scoring and clear rationales.

- **Transparent Risk Scoring**  
  Applies a fixed-weight, reproducible formula using base severity, asset criticality, mapped technique risk, and lateral/volume spread.

- **Playbook Recommendations**  
  Retrieves the most relevant containment/eradication playbooks via hybrid technique/tag matching.

- **Automated Ticket Drafting**  
  Generates fully structured tickets (Jira/ServiceNow) with mapped MITRE techniques, IOC summaries, key events, recommended actions, and references.

- **Sensor Health & Coverage Analysis**  
  Reports active/inactive/delayed coverage by OU/VPC and highlights blind spots.

- **Analyst-Friendly Output**  
  Provides a single JSON output with normalized alerts, triage data, summaries, rankings, and optional Q&A results.

---

## 🧠 How AI Was Used in Development

- **Prompt-Engineered Schemas**  
  The entire normalized alert schema, ATT&CK mapping rules, and risk scoring formulas were designed using structured AI prompts for deterministic output.

- **Few-Shot JSON Examples**  
  AI generated realistic example telemetry and triage outputs (`data/samples/telemetry.json`, `data/samples/llm_output.json`) to validate the pipeline.

- **Code Scaffolding**  
  Core service modules in `app/services` (e.g., `ingest.py`, `score.py`, `attack_map.py`) were initially drafted via AI, then refined and tested manually.

- **README & Documentation Drafting**  
  This very README was AI-assisted, with refinements to ensure recruiter-friendly, technically accurate presentation.

---

## 🛠 Architecture

```text
[Telemetry Sources: Wazuh / Zeek / AWS CloudTrail]
        │
        ▼
[Ingest Service] → normalize → enrich from asset inventory
        │
        ▼
[MITRE Mapping] → map observables to tactics/techniques
        │
        ▼
[Risk Scoring] → deterministic formula + escalation
        │
        ▼
[Playbook Retrieval] → match to mapped techniques
        │
        ▼
[Ticket Drafting] → Jira/ServiceNow format
        │
        ▼
[Output] → JSON file with all sections + rankings
