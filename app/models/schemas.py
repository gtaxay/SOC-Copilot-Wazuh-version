from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class Asset(BaseModel):
    hostname: Optional[str] = None
    instance_id: Optional[str] = None
    ip: Optional[str] = None
    ou_or_vpc: Optional[str] = None
    criticality: Optional[int] = None
    owner: Optional[str] = None

class Actor(BaseModel):
    user: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None

class Observables(BaseModel):
    hashes: List[str] = []
    domains: List[str] = []
    ips: List[str] = []
    paths: List[str] = []
    commands: List[str] = []
    detections: List[str] = []

class NormalizedAlert(BaseModel):
    alert_id: str
    source: str
    vendor: Optional[str] = None
    timestamp: str
    asset: Asset
    actor: Actor
    observables: Observables
    base_severity: int
    raw: Dict[str, Any] = {}

class MitreMap(BaseModel):
    tactic: str
    technique: str
    confidence: float
    rationale: str

class RiskScore(BaseModel):
    value: float
    drivers: List[str]
    rationale: str

class Ticket(BaseModel):
    system: str
    title: str
    severity: str
    classification: str
    mapped_mitre: List[str]
    evidence: Dict[str, Any]
    recommended_actions: List[str]
    owner_suggestion: Optional[str] = None
    references: List[str] = []

class IncidentSummary(BaseModel):
    who: str
    what: str
    when: str
    where: str
    impact: str
    severity_rank: str

class TriageItem(BaseModel):
    alert_id: str
    mitre_mapping: List[MitreMap]
    risk_score: RiskScore
    playbook_recommendations: List[Dict[str, str]]
    incident_summary: IncidentSummary
    ticket_draft: Ticket

class SensorCoverageByUnit(BaseModel):
    name: str
    active: int
    inactive: int
    delayed: int
    coverage_pct_active: float

class SensorHealth(BaseModel):
    coverage: Dict[str, Any]
    blind_spots: List[str]
    recommended_fixes: List[str]

class QAResult(BaseModel):
    query: Optional[str] = None
    query_plan: Optional[str] = None
    result_set: List[Dict[str, str]] = []
    answer: Optional[str] = None

class PipelineOutput(BaseModel):
    normalized_alerts: List[NormalizedAlert]
    triage: List[TriageItem]
    sensor_health: Optional[SensorHealth] = None
    qa: QAResult
    ranking: List[Dict[str, Any]]
    errors: List[str] = []
