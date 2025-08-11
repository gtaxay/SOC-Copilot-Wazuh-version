import json, requests, os, streamlit as st

API = os.getenv("API_URL", "http://127.0.0.1:8000")
st.title("SOC Copilot — Analyst Console (Wazuh)")

tab1, tab2 = st.tabs(["Telemetry", "Context & Options"])

with tab1:
    telemetry_raw = st.text_area(
        "Telemetry JSON array",
        height=240,
        value='''[
  {
    "alert_id": "wz-8842",
    "source": "wazuh",
    "vendor": "Wazuh",
    "timestamp": "2025-08-10T12:03:21Z",
    "rule": {"level": 7, "description": "Windows command execution"},
    "agent": {"id":"001","name":"FIN-LAP-22","ip":"10.10.12.34"},
    "data": {"win": {"eventdata": {
      "CommandLine": "powershell.exe -enc SQBt...",
      "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
      "User": "CORP\\\\jdoe",
      "DestinationIp": "203.0.113.45",
      "Hashes": "MD5=...,SHA1=...,SHA256=abc123..."
    }, "system": {"computer": "FIN-LAP-22"}}}
  }
]'''
    )

with tab2:
    context_raw = st.text_area(
        "Context JSON (asset_inventory, sensor_status, playbooks) — optional",
        height=260,
        value='''{
  "asset_inventory": {
    "FIN-LAP-22": { "owner": "CORP\\\\jdoe", "ou_or_vpc": "Finance-Endpoints", "criticality": 8 }
  },
  "sensor_status": {
    "FIN-LAP-22": { "status": "active", "last_seen": "2025-08-10T12:04:00Z", "sensor_version": "6.55" }
  },
  "playbooks": [
    {
      "id": "pb-powershell-lolbin",
      "title": "Containment for Malicious PowerShell",
      "text": "1) Isolate host; 2) Kill process; 3) Collect PS logs; 4) Block IOC...",
      "tags": ["endpoint","wazuh"],
      "mapped_techniques": ["T1059.003","T1105"]
    }
  ]
}'''
    )
    ticket_system = st.selectbox("Ticket system", ["jira", "servicenow"], index=0)

run = st.button("Run Triage")

if run:
    try:
        telemetry = json.loads(telemetry_raw or "[]")
        context = json.loads(context_raw) if context_raw.strip() else {}
        options = {"ticket_system": ticket_system}
        payload = {"telemetry": telemetry, "context": context, "options": options}
        r = requests.post(f"{API}/triage", json=payload, timeout=60)
        st.subheader("Result")
        st.json(r.json())
    except Exception as e:
        st.error(f"Input error: {e}")
