"""Pydantic v2 API schemas."""
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# ------------------------------------------------------------- core contracts


class Evidence(BaseModel):
    """A single verifiable fact an agent's reasoning is grounded in."""
    source: str = Field(..., min_length=1, max_length=96)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    fact: str = Field(..., min_length=1)
    reliability: Literal["high", "medium", "low"] = "high"
    raw_reference: str = Field(default="", max_length=160)


class Decision(BaseModel):
    """A structured agent decision with its evidence trail."""
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[int] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    requires_approval: bool = False


# ------------------------------------------------------------------- metadata


class MetaInfo(BaseModel):
    app_name: str
    version: str
    llm_mode: str
    mock_mode: bool
    estate_size: int
    sim_seed: int
    database: str


class HealthInfo(BaseModel):
    status: str
    database: str


class ReadinessInfo(BaseModel):
    ready: bool
    endpoints_seeded: int
    patches_seeded: int
    detail: str = ""


class SeedRequest(BaseModel):
    estate_size: int | None = Field(default=None, ge=50, le=20000)


class SeedResult(BaseModel):
    endpoints: int
    patches: int
    patch_states: int
    findings: int
    departments: int
    duration_ms: int


# ---------------------------------------------------------------------- fleet


class EndpointOut(BaseModel):
    id: int
    hostname: str
    os: str
    os_build: str
    role: str
    department: str
    criticality: str
    eol: bool
    disk_free_gb: float
    ram_gb: float
    cpu_age_years: float
    health_score: int
    historical_patch_failures: int
    pending_reboot_days: int
    compliance_flags: list[str]
    software: list[dict[str, str]]


class EndpointDetailOut(EndpointOut):
    patch_states: list[dict[str, Any]]
    findings: list[dict[str, Any]]


class FleetSummary(BaseModel):
    total_endpoints: int
    by_os: dict[str, int]
    by_department: dict[str, int]
    by_criticality: dict[str, int]
    eol_count: int
    pending_reboot_over_30d: int
    avg_health: float
    avg_disk_free_gb: float


# ------------------------------------------------------------------ patches


class PatchCVEOut(BaseModel):
    cve_id: str
    cvss: float
    known_exploited: bool
    description: str = ""


class PatchKnownIssueOut(BaseModel):
    kind: str
    app_name: str
    version_below: str
    failure_class: str
    description: str = ""


class PatchOut(BaseModel):
    patch_id: str
    name: str
    target_os: str
    severity: str
    reboot_required: bool
    release_date: date
    typical_install_minutes: int
    disk_space_required_mb: int
    supersedes: list[str]
    prerequisites: list[str]
    superseded_by: str | None = None
    at_risk_policy_default: str = "canary_prove"
    notes: str = ""
    cves: list[PatchCVEOut] = Field(default_factory=list)
    known_issues: list[PatchKnownIssueOut] = Field(default_factory=list)


class CompatibilityCell(BaseModel):
    department: str
    os: str
    total: int
    applicable: int
    incompatible: int
    at_risk: int
    blocked_disk: int
    missing_prereq: int


class CompatibilityMatrix(BaseModel):
    patch_id: str
    eligible_total: int
    cells: list[CompatibilityCell]
    cohorts: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------- vulnerabilities


class VulnerabilityGroup(BaseModel):
    cve_id: str
    patch_id: str
    cvss: float
    known_exploited: bool
    affected_endpoints: int
    departments: dict[str, int]


# ---------------------------------------------------------------- campaigns


class CampaignCreate(BaseModel):
    patch_id: str = Field(..., min_length=3, max_length=48)
    name: str | None = Field(default=None, max_length=160)
    at_risk_policy: Literal["canary_prove", "exclude"] = "canary_prove"


class CampaignOut(BaseModel):
    id: int
    name: str
    patch_id: str
    status: str
    at_risk_policy: str
    emergency_approved: bool
    blocked_reason: str
    stop_reason: str
    eligible_count: int
    created_at: datetime
    completed_at: datetime | None = None


class ApprovalCreate(BaseModel):
    reason: str = Field(default="", max_length=1000)


class ApprovalOut(BaseModel):
    id: int
    campaign_id: int
    approval_type: str
    status: str
    requested_reason: str
    requested_by: str
    decided_by: str | None = None
    decision_note: str = ""
    created_at: datetime
    decided_at: datetime | None = None


class RingPlanOut(BaseModel):
    ring: str
    position: int
    size: int
    threshold: float
    criteria_note: str
    endpoint_ids: list[int] = Field(default_factory=list)


class DeviceInstallResultOut(BaseModel):
    endpoint_id: int
    hostname: str | None = None
    ring: str
    outcome: str
    failure_class: str | None = None
    attempts: int
    install_seconds: int
    error_detail: str


class RingExecutionOut(BaseModel):
    id: int
    ring: str
    position: int
    status: str
    device_count: int
    success_count: int
    pending_reboot_count: int
    failure_count: int
    failure_rate: float
    threshold: float
    stop_triggered: bool
    stop_reason: str
    started_at: datetime | None = None
    finished_at: datetime | None = None


class RCARecordOut(BaseModel):
    campaign_id: int
    ring: str
    failure_class: str
    affected_count: int
    root_cause: str
    correlated_factor: dict[str, Any]
    confidence: float
    recommended_action: str


class RollbackOut(BaseModel):
    id: int
    campaign_id: int
    rings: list[str]
    reason: str
    failure_rate_before: float
    restored_count: int
    validation_passed: bool
    performed_at: datetime


class ValidationOut(BaseModel):
    endpoint_id: int
    patch_id: str
    phase: str
    passed: bool
    checks: list[dict[str, Any]]
    checked_at: datetime


class EventOut(BaseModel):
    id: int
    campaign_id: int | None
    type: str
    message: str
    payload: dict[str, Any]
    created_at: datetime


# ------------------------------------------------------------------- metrics


class MetricsSummary(BaseModel):
    compliance_overall_pct: float
    compliance_by_department: dict[str, float]
    compliance_by_os: dict[str, float]
    mean_time_to_patch_days: float
    failed_patch_rate_by_ring: dict[str, float]
    rollback_rate_pct: float
    canary_detection_effectiveness_pct: float
    unsafe_deployment_preventions: int
    exposure_window_critical_kev_before_days: float
    exposure_window_critical_kev_after_days: float
    generated_at: datetime


# ---------------------------------------------------------------- evaluation


class EvaluationCheck(BaseModel):
    check: str
    passed: bool
    detail: str = ""


class EvaluationScenarioResult(BaseModel):
    scenario: str
    passed: bool
    checks: list[EvaluationCheck] = Field(default_factory=list)


class EvaluationRunOut(BaseModel):
    id: int
    all_passed: bool
    passed_count: int
    failed_count: int
    total_checks: int
    scenario_results: list[EvaluationScenarioResult]
    duration_ms: int
    created_at: datetime


# --------------------------------------------------------------------- tools


class ToolSpecOut(BaseModel):
    name: str
    purpose: str
    input_schema: dict[str, Any]
    permission: str
    risk_level: str
    timeout_s: float


class ToolExecuteRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)
