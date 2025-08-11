from typing import List
from app.models.schemas import NormalizedAlert, MitreMap

def map_attack(alert: NormalizedAlert) -> List[MitreMap]:
    out=[]
    cmd = " ".join(alert.observables.commands) if alert.observables.commands else ""
    if "powershell" in cmd.lower():
        out.append(MitreMap(
            tactic="TA0002_Execution",
            technique="T1059.003_PowerShell",
            confidence=0.85,
            rationale="Encoded/interactive PowerShell observed in endpoint telemetry."
        ))
    if alert.observables.ips:
        out.append(MitreMap(
            tactic="TA0011_Command and Control",
            technique="T1105_Ingress Tool Transfer",
            confidence=0.5,
            rationale="External IP contact during suspicious execution."
        ))
    return out
