from typing import Dict, Any, List, Optional
from app.models.schemas import NormalizedAlert, Asset, Actor, Observables

def _pick(*vals):
    for v in vals:
        if v is not None and v != "":
            return v
    return None

def _parse_hashes(hashes_field: Optional[str]) -> List[str]:
    if not hashes_field:
        return []
    out = []
    for part in hashes_field.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip().upper() == "SHA256":
                out.append(v.strip())
    return out

def normalize_alert(src: Dict[str, Any]) -> NormalizedAlert:
    source = (_pick(src.get("source"), "wazuh") or "wazuh").lower()
    vendor = _pick(src.get("vendor"), "Wazuh")
    timestamp = _pick(src.get("timestamp"), src.get("@timestamp"))

    agent = src.get("agent") or {}
    data = src.get("data") or {}
    win = (data.get("win") or {})
    ev = (win.get("eventdata") or {})
    sys = (win.get("system") or {})

    hostname = _pick(agent.get("name"), sys.get("computer"))
    user = _pick(ev.get("User"), src.get("user"))
    cmd = _pick(ev.get("CommandLine"), src.get("CommandLine"))
    image = _pick(ev.get("Image"), src.get("Image"))
    dest_ip = _pick(ev.get("DestinationIp"), ev.get("dest_ip"), src.get("ip"))
    hashes = _parse_hashes(ev.get("Hashes"))

    rule = src.get("rule") or {}
    level = rule.get("level")
    try:
        base_severity = int(level) if level is not None else 5
    except Exception:
        base_severity = 5
    base_severity = max(1, min(10, base_severity))

    obs = Observables(
        hashes=hashes,
        ips=[dest_ip] if dest_ip else [],
        domains=[],
        paths=[],
        commands=[cmd] if cmd else [],
        detections=[rule.get("description")] if rule.get("description") else []
    )

    asset = Asset(
        hostname=hostname,
        instance_id=None,
        ip=agent.get("ip"),
        ou_or_vpc=None,
        criticality=None,
        owner=user
    )

    actor = Actor(
        user=user,
        process=image or (cmd.split()[0] if cmd else None),
        pid=None
    )

    return NormalizedAlert(
        alert_id=str(_pick(src.get("alert_id"), src.get("id"), "unknown")),
        source=source,
        vendor=vendor,
        timestamp=str(timestamp) if timestamp else "",
        asset=asset,
        actor=actor,
        observables=obs,
        base_severity=base_severity,
        raw=src
    )
