from app.models.schemas import NormalizedAlert, RiskScore

HIGH_TECH_WEIGHTS = {"T1486":9,"T1003":8,"T1078":7,"T1047":6}
def technique_weight(mapped: list[str]) -> int:
    if not mapped: return 0
    best = 5
    for t in mapped:
        for k,v in HIGH_TECH_WEIGHTS.items():
            if t.startswith(k): best = max(best, v)
        if t.startswith("T1059"): best = max(best, 6)
    return best

def compute_risk(alert: NormalizedAlert, mapped: list[str], spread: int=0, criticality_fallback=5) -> RiskScore:
    w = {"base":0.40,"criticality":0.30,"technique":0.20,"spread":0.10}
    crit = alert.asset.criticality or criticality_fallback
    tech = technique_weight(mapped)
    raw = (w["base"]*alert.base_severity) + (w["criticality"]*crit) + (w["technique"]*tech) + (w["spread"]*spread)
    val = max(0, min(10, round(raw, 1)))
    return RiskScore(value=val, drivers=["base","criticality","technique","spread"],
                     rationale=f"Base={alert.base_severity}, Crit={crit}, Tech={tech}, Spread={spread}")
