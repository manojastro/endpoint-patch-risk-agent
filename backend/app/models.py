"""SQLAlchemy ORM models - the full persistence schema."""
from datetime import date, datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- fleet domain

from app.db import Base  # noqa: E402


class DepartmentRow(Base):
    __tablename__ = "departments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    default_criticality: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    endpoint_count: Mapped[int] = mapped_column(Integer, default=0)


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    os: Mapped[str] = mapped_column(String(32), index=True)
    os_build: Mapped[str] = mapped_column(String(32))
    role: Mapped[str] = mapped_column(String(32), index=True)
    department: Mapped[str] = mapped_column(String(64), index=True)
    criticality: Mapped[str] = mapped_column(String(16), index=True)  # critical/high/medium/low
    eol: Mapped[bool] = mapped_column(Boolean, default=False)
    disk_free_gb: Mapped[float] = mapped_column(Float)
    ram_gb: Mapped[float] = mapped_column(Float)
    cpu_age_years: Mapped[float] = mapped_column(Float)
    health_score: Mapped[int] = mapped_column(Integer)  # 0..100
    historical_patch_failures: Mapped[int] = mapped_column(Integer, default=0)
    pending_reboot_days: Mapped[int] = mapped_column(Integer, default=0)
    compliance_flags: Mapped[list] = mapped_column(JSON, default=list)
    software: Mapped[list] = mapped_column(JSON, default=list)  # [{name, version}]
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    patch_states: Mapped[list["EndpointPatchState"]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )


class Patch(Base):
    __tablename__ = "patches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patch_id: Mapped[str] = mapped_column(String(48), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    target_os: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16))  # critical/high/moderate/low
    reboot_required: Mapped[bool] = mapped_column(Boolean, default=False)
    release_date: Mapped[date] = mapped_column(Date)
    typical_install_minutes: Mapped[int] = mapped_column(Integer, default=20)
    disk_space_required_mb: Mapped[int] = mapped_column(Integer, default=1024)
    supersedes: Mapped[list] = mapped_column(JSON, default=list)  # [patch_id]
    prerequisites: Mapped[list] = mapped_column(JSON, default=list)  # [patch_id]
    superseded_by: Mapped[str | None] = mapped_column(String(48), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    at_risk_policy_default: Mapped[str] = mapped_column(String(24), default="canary_prove")

    cves: Mapped[list["PatchCVE"]] = relationship(back_populates="patch", cascade="all, delete-orphan")
    known_issues: Mapped[list["PatchKnownIssue"]] = relationship(
        back_populates="patch", cascade="all, delete-orphan"
    )


class PatchCVE(Base):
    __tablename__ = "patch_cves"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patch_row_id: Mapped[int] = mapped_column(ForeignKey("patches.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    cvss: Mapped[float] = mapped_column(Float)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(Text, default="")
    patch: Mapped[Patch] = relationship(back_populates="cves")


class PatchKnownIssue(Base):
    """Publicly documented incompatibility for a patch (visible pre-rollout)."""
    __tablename__ = "patch_known_issues"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patch_row_id: Mapped[int] = mapped_column(ForeignKey("patches.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24))  # app_version | driver | av_agent
    app_name: Mapped[str] = mapped_column(String(96))
    version_below: Mapped[str] = mapped_column(String(32))  # versions < this are affected
    failure_class: Mapped[str] = mapped_column(String(24))  # taxonomy class if installed anyway
    description: Mapped[str] = mapped_column(Text, default="")
    patch: Mapped[Patch] = relationship(back_populates="known_issues")


class Supersedence(Base):
    __tablename__ = "supersedence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    newer_patch_id: Mapped[str] = mapped_column(String(48), index=True)
    older_patch_id: Mapped[str] = mapped_column(String(48), index=True)


class EndpointPatchState(Base):
    __tablename__ = "endpoint_patch_states"
    __table_args__ = (UniqueConstraint("endpoint_id", "patch_id", name="uq_ep_patch"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    patch_id: Mapped[str] = mapped_column(String(48), index=True)
    state: Mapped[str] = mapped_column(String(24))  # not_applicable/up_to_date/downloaded/failed/pending_reboot/installed
    last_changed: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    detail: Mapped[str] = mapped_column(Text, default="")
    endpoint: Mapped[Endpoint] = relationship(back_populates="patch_states")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    patch_id: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    cvss: Mapped[float] = mapped_column(Float)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open/remediated
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    endpoint: Mapped[Endpoint] = relationship(back_populates="findings")


# ------------------------------------------------------------- rollout domain

class Campaign(Base):
    __tablename__ = "campaigns"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    patch_id: Mapped[str] = mapped_column(String(48), index=True)
    status: Mapped[str] = mapped_column(String(32), default="DETECTED", index=True)
    at_risk_policy: Mapped[str] = mapped_column(String(24), default="canary_prove")
    emergency_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    blocked_reason: Mapped[str] = mapped_column(Text, default="")
    stop_reason: Mapped[str] = mapped_column(Text, default="")
    excluded_endpoint_ids: Mapped[list] = mapped_column(JSON, default=list)
    exclusion_reasons: Mapped[dict] = mapped_column(JSON, default=dict)
    eligible_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    ring_plans: Mapped[list["RingPlan"]] = relationship(back_populates="campaign")
    ring_executions: Mapped[list["RingExecution"]] = relationship(back_populates="campaign")


class RingPlan(Base):
    __tablename__ = "ring_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    ring: Mapped[str] = mapped_column(String(12))  # RING_0..RING_4
    position: Mapped[int] = mapped_column(Integer)  # 0..4 ordering
    endpoint_ids: Mapped[list] = mapped_column(JSON, default=list)
    size: Mapped[int] = mapped_column(Integer, default=0)
    criteria_note: Mapped[str] = mapped_column(Text, default="")
    threshold: Mapped[float] = mapped_column(Float, default=0.05)
    campaign: Mapped[Campaign] = relationship(back_populates="ring_plans")


class RingExecution(Base):
    __tablename__ = "ring_executions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    ring: Mapped[str] = mapped_column(String(12))
    position: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="pending")  # pending/running/succeeded/halted/rolled_back/skipped
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    pending_reboot_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_rate: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.05)
    stop_triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    stop_reason: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    campaign: Mapped[Campaign] = relationship(back_populates="ring_executions")


class DeviceInstallResult(Base):
    __tablename__ = "device_install_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    ring_execution_id: Mapped[int] = mapped_column(ForeignKey("ring_executions.id"), index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    patch_id: Mapped[str] = mapped_column(String(48), index=True)
    ring: Mapped[str] = mapped_column(String(12))
    outcome: Mapped[str] = mapped_column(String(32))  # success / pending_reboot / failed / rolled_back
    failure_class: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    install_seconds: Mapped[int] = mapped_column(Integer, default=0)
    error_detail: Mapped[str] = mapped_column(Text, default="")


class Validation(Base):
    __tablename__ = "validations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    patch_id: Mapped[str] = mapped_column(String(48))
    phase: Mapped[str] = mapped_column(String(16), default="post_patch")  # post_patch/post_rollback
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    checks: Mapped[list] = mapped_column(JSON, default=list)  # [{check,passed,detail}]
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RCARecord(Base):
    __tablename__ = "rca_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    ring: Mapped[str] = mapped_column(String(12))
    failure_class: Mapped[str] = mapped_column(String(32), index=True)
    affected_count: Mapped[int] = mapped_column(Integer)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    correlated_factor: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Rollback(Base):
    __tablename__ = "rollbacks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    rings: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text, default="")
    failure_rate_before: Mapped[float] = mapped_column(Float, default=0.0)
    restored_count: Mapped[int] = mapped_column(Integer, default=0)
    validation_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    performed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ------------------------------------------------------- workflow / reasoning

ALLOWED_CAMPAIGN_STATUSES = (
    "DETECTED", "INVESTIGATING", "DIAGNOSED", "PLANNED", "VALIDATING",
    "AWAITING_APPROVAL", "APPROVED", "EXECUTING", "VERIFYING", "COMPLETED",
    "FAILED", "ROLLED_BACK",
)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(48), index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    topic: Mapped[str] = mapped_column(String(160))
    stage: Mapped[str] = mapped_column(String(48))
    status: Mapped[str] = mapped_column(String(24), default="open")  # open/closed
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    stage_runs: Mapped[list["StageRun"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    decisions: Mapped[list["DecisionRow"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class StageRun(Base):
    __tablename__ = "stage_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    agent: Mapped[str] = mapped_column(String(48))
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), default="done")
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_mode: Mapped[str] = mapped_column(String(16), default="mock")
    llm_rationale: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="stage_runs")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    source: Mapped[str] = mapped_column(String(96))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    fact: Mapped[str] = mapped_column(Text)
    reliability: Mapped[str] = mapped_column(String(16), default="high")  # high/medium/low
    raw_reference: Mapped[str] = mapped_column(String(160), default="")
    investigation: Mapped[Investigation] = relationship(back_populates="evidence")


class DecisionRow(Base):
    __tablename__ = "decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    decision: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    alternatives: Mapped[list] = mapped_column(JSON, default=list)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="decisions")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (UniqueConstraint("campaign_id", "endpoint_id", "patch_id", name="uq_risk_ep_patch"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    patch_id: Mapped[str] = mapped_column(String(48), index=True)
    score: Mapped[float] = mapped_column(Float)
    bucket: Mapped[str] = mapped_column(String(4), index=True)  # P1..P4
    factor_values: Mapped[dict] = mapped_column(JSON, default=dict)
    weights: Mapped[dict] = mapped_column(JSON, default=dict)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    approval_type: Mapped[str] = mapped_column(String(32), default="deployment")  # deployment|emergency_override|rollback
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/approved/rejected
    requested_reason: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(64), default="rollout-agent")
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Action(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="recommended")  # recommended/executed/dismissed
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Outcome(Base):
    __tablename__ = "outcomes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    patch_id: Mapped[str] = mapped_column(String(48))
    final_outcome: Mapped[str] = mapped_column(String(24))  # patched/pending_reboot/failed/rolled_back/excluded/unaffected
    detail: Mapped[str] = mapped_column(Text, default="")
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ------------------------------------------------------------------ ops/audit

class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    value_json: Mapped[dict] = mapped_column(JSON, default=dict)
    campaign_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario_results: Mapped[list] = mapped_column(JSON, default=list)
    passed_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    all_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ToolCall(Base):
    __tablename__ = "tool_calls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(64), index=True)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str] = mapped_column(Text, default="")
    caller: Mapped[str] = mapped_column(String(64), default="agent")
    risk_level: Mapped[str] = mapped_column(String(16), default="read")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    result_summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


Index("ix_endpoint_dept_crit", Endpoint.department, Endpoint.criticality)
Index("ix_finding_status_exploit", Finding.status, Finding.known_exploited)
