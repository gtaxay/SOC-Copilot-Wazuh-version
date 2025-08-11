from fastapi import FastAPI
from typing import Dict, Any, List
from app.services.ingest import normalize_alert
from app.services.attack_map import map_attack
from app.services.score import compute_risk
from app.models.schemas import PipelineOutput, TriageItem, IncidentSummary, Ticket, QAResult

app = FastAPI(title="SOC Copilot API")

def _apply_asset_context(alert, asset_inventory: Dict[str, Any]) -> None:
    """Merge asset_inventory fields (criticality, ou_or_vpc, owner) into the alert."""
    host = alert.asset.hostname
    if not host:
        return
    meta = (asset_inventory or {}).get(host) or {}
    if "criticality" in meta and meta["criticality"] is not None:
        alert.asset.criticality = meta["criticality"]
    if "ou_or_vpc" in meta and meta["ou_or_vpc"]:
        alert.asset.ou_or_vpc = meta["ou_or_vpc"]
    if "owner" in meta and meta["owner"]:
        alert.asset.owner = meta["owner"]

def _sensor_inactive_recent(sensor_status: Dict[str, Any], host: str) -> bool:
    st = (sensor_status or {}).get(host) or {}
    return (st.get("status") or "").lower() == "inactive"

def _pick_playbooks(mapped_ids: List[str], context: Dict[str, Any], top_k: int = 3):
    """Simple, deterministic picker: overlap on techniques + tag match for 'wazuh'."""
    pbs = (context or {}).get("playbooks") or []
    mapped_set = set(mapped_ids)
    scored = []
    for pb in pbs:
        mt = set(pb.get("mapped_techniques") or [])
        overlap = len(mapped_set.intersection(mt))
        tag_score = 1 if "wazuh" in (pb.get("tags") or []) else 0
        score = overlap * 2 + tag_score
        if score > 0:
            text = pb.get("text", "")
            excerpt = text if len(text) <= 400 else text[:400] + "..."
            scored.append({
                "score": score,
                "playbook_id": pb.get("id", ""),
                "title": pb.get("title", ""),
                "excerpt": excerpt
            })
    scored.sort(key=lambda x: -x["score"])
    return [{"playbook_id": s["playbook_id"], "title": s["title"], "excerpt": s["excerpt"]} for s in scored[:top_k]]

@app.post("/triage", response_model=PipelineOutput)
def triage(payload: Dict[str, Any]) -> PipelineOutput:
    telemetry = payload.get("telemetry", []) or []
    context = payload.get("context", {}) or {}
    options = payload.get("options", {}) or {}

    asset_inventory = context.get("asset_inventory") or {}
    sensor_status = context.get("sensor_status") or {}
    top_k_playbooks = int(options.get("top_k_playbooks", 3))

    normalized = [normalize_alert(x) for x in telemetry]

    triage_items, ranking, errors = [], [], []

    for a in normalized:
        # 1) Enrich with context (fills criticality / ou_or_vpc / owner if provided)
        _apply_asset_context(a, asset_inventory)

        # 2) ATT&CK mapping
        mapping = map_attack(a)
        mapped_ids = [m.technique.split("_")[0] for m in mapping]

        # 3) Risk score + escalation rules (DC/Tier0/crit>=9, T1486, inactive sensor)
        risk = compute_risk(a, mapped_ids)
        escalate_reasons = []
        if (a.asset.criticality or 5) >= 9:
            escalate_reasons.append("Tier-0/critical asset")
        if any(t.startswith("T1486") for t in mapped_ids):
            escalate_reasons.append("Ransomware indicator (T1486)")
        if a.asset.hostname and _sensor_inactive_recent(sensor_status, a.asset.hostname):
            escalate_reasons.append("Sensor inactive in last 24h")
        if escalate_reasons:
            risk.value = min(10.0, round(risk.value + 1.0, 1))
            risk.rationale = (risk.rationale + " | escalation: " + "; ".join(escalate_reasons)).strip()

        # 4) Playbook recommendations (based on technique/tag overlap)
        playbooks = _pick_playbooks(mapped_ids, context, top_k_playbooks)

        # 5) Incident summary
        inc = IncidentSummary(
            who=f"{a.actor.user or 'unknown'} on {a.asset.hostname or 'unknown'}",
            what="; ".join(a.observables.commands or a.observables.detections or ["suspicious activity"]),
            when=a.timestamp,
            where=a.asset.ou_or_vpc or "unknown",
            impact="Potential security incident on monitored asset",
            severity_rank="1"
        )

        # 6) Ticket draft
        ticket = Ticket(
            system=options.get("ticket_system","jira"),
            title=f"[{('High' if risk.value>=7 else 'Medium')}] Incident on {a.asset.hostname or 'host'}",
            severity=("Critical" if risk.value>=9 else "High" if risk.value>=7 else "Medium" if risk.value>=4 else "Low"),
            classification="Execution / Possible C2",
            mapped_mitre=mapped_ids,
            evidence={"ioc_summary":{
                "ips":a.observables.ips,
                "domains":a.observables.domains,
                "hashes":a.observables.hashes,
                "paths":a.observables.paths
            },
            "key_events":[f"{a.timestamp} :: {a.observables.commands[0]}" if a.observables.commands else f"{a.timestamp} :: event"]},
            recommended_actions=["Isolate host","Terminate malicious processes","Collect logs","Block IOCs"],
            references=[p.get("playbook_id") for p in playbooks if p.get("playbook_id")]
        )

        triage_items.append(TriageItem(
            alert_id=a.alert_id,
            mitre_mapping=mapping,
            risk_score=risk,
            playbook_recommendations=playbooks,
            incident_summary=inc,
            ticket_draft=ticket
        ))
        ranking.append({"alert_id": a.alert_id, "risk_score": risk.value, "priority": 1})

    return PipelineOutput(
        normalized_alerts=normalized,
        triage=triage_items,
        sensor_health=None,
        qa=QAResult(),
        ranking=sorted(ranking, key=lambda x: (-x["risk_score"])),
        errors=errors
    )
