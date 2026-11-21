"""Server-enforced campaign workflow state machine + agent orchestration.

LangGraph mapping note: each function below corresponds to a graph node; the
persisted `campaigns.status` column is the serialized graph state, and the
AWAITING_APPROVAL status is the human-in-the-loop interrupt point. Edges:
DETECTED -> INVESTIGATING -> DIAGNOSED -> PLANNED -> AWAITING_APPROVAL ->
APPROVED -> EXECUTING <-> VERIFYING -> COMPLETED | FAILED -> ROLLED_BACK.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.base import make_investigation
from app.agents.compatibility_agent import CompatibilityAgent
from app.agents.dependency_agent import DependencyAgent
from app.agents.inventory_agent import InventoryAgent
from app.agents.planning_agent import PlanningAgent
from app.agents.rca_agent import RcaAgent
from app.agents.risk_agent import RiskAgent
from app.agents.rollback_agent import RollbackAgent
from app.agents.validation_agent import ValidationAgent
from app.agents.vulnerability_agent import VulnerabilityAgent
from app.engine.rollout_engine import (
    complete_campaign, compute_eligibility, execute_ring, load_world,
    next_pending_ring,
)
from app.metrics import UNSAFE_PREVENTIONS_TOTAL
from app.models import (
    ALLOWED_CAMPAIGN_STATUSES, Approval, Campaign, Event, Patch,
    RingExecution, utcnow,
)

TRANSITIONS: dict[str, set[str]] = {
    "DETECTED": {"INVESTIGATING", "FAILED"},
    "INVESTIGATING": {"DIAGNOSED", "FAILED"},
    "DIAGNOSED": {"PLANNED", "FAILED"},
    "PLANNED": {"VALIDATING", "AWAITING_APPROVAL", "FAILED"},
    "VALIDATING": {"AWAITING_APPROVAL", "PLANNED", "FAILED"},
    "AWAITING_APPROVAL": {"APPROVED", "PLANNED", "FAILED"},
    "APPROVED": {"EXECUTING", "FAILED"},
    "EXECUTING": {"VERIFYING", "FAILED"},
    "VERIFYING": {"EXECUTING", "COMPLETED", "FAILED"},
    "COMPLETED": set(),
    "FAILED": {"ROLLED_BACK", "INVESTIGATING", "PLANNED"},
    "ROLLED_BACK": {"PLANNED", "COMPLETED"},
}


class WorkflowViolation(Exception):
    """Illegal state transition; safe to surface as HTTP 409."""


def transition(db: Session, campaign: Campaign, new_status: str, note: str = "") -> None:
    if new_status not in ALLOWED_CAMPAIGN_STATUSES:
        raise WorkflowViolation(f"unknown status {new_status}")
    allowed = TRANSITIONS.get(campaign.status, set())
    if new_status not in allowed:
        raise WorkflowViolation(
            f"illegal transition {campaign.status} -> {new_status}"
        )
    previous = campaign.status
    campaign.status = new_status
    db.add(Event(campaign_id=campaign.id, type="status_transition",
                 message=f"{previous} -> {new_status}" + (f" ({note})" if note else ""),
                 payload={"from": previous, "to": new_status}))
    db.flush()


def add_event(db: Session, campaign_id: int | None, type_: str, message: str,
              payload: dict | None = None) -> None:
    db.add(Event(campaign_id=campaign_id, type=type_, message=message,
                 payload=payload or {}))
    db.flush()


# ------------------------------------------------------------------ lifecycle

def create_campaign(db: Session, patch_id: str, name: str | None,
                    at_risk_policy: str = "canary_prove") -> Campaign:
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == patch_id))
    if patch_row is None:
        raise ValueError(f"unknown patch_id {patch_id}")
    policy = at_risk_policy or patch_row.at_risk_policy_default
    campaign = Campaign(
        name=name or f"Rollout of {patch_id}", patch_id=patch_id,
        status="DETECTED", at_risk_policy=policy,
    )
    db.add(campaign)
    db.flush()
    add_event(db, campaign.id, "campaign_created",
              f"Campaign created for {patch_id} (policy={policy})")
    return campaign


def run_investigation(db: Session, campaign: Campaign) -> dict:
    """DETECTED -> INVESTIGATING -> DIAGNOSED via the deterministic agents."""
    transition(db, campaign, "INVESTIGATING")
    inv = make_investigation(db, topic=f"Investigation for {campaign.patch_id}",
                             campaign_id=campaign.id)
    inventory = InventoryAgent().run(db, inv, sequence=1)
    vuln = VulnerabilityAgent().run(db, inv, sequence=2)

    patch_row, endpoints, states_by_ep = load_world(db, campaign.patch_id)
    compat = CompatibilityAgent().run(
        db, inv, patch_row, endpoints, states_by_ep, campaign.at_risk_policy,
        sequence=3,
    )
    dependency = DependencyAgent().run(db, inv, endpoints, sequence=4)

    eligible, _excl, reasons, _rmap = compute_eligibility(
        db, patch_row, endpoints, states_by_ep, campaign.at_risk_policy
    )
    risk = RiskAgent().run(db, inv, campaign.id, patch_row, eligible, sequence=5)

    campaign.exclusion_reasons = reasons
    inv.stage = "DIAGNOSED"
    inv.summary = (
        f"Fleet {inventory['total_endpoints']}; eligible "
        f"{compat['eligible_total']}; cohorts {len(compat['cohorts'])}; "
        f"P1 share {risk['p1_share']:.0%}."
    )
    transition(db, campaign, "DIAGNOSED")
    return {
        "investigation_id": inv.id,
        "inventory": inventory,
        "vulnerabilities": {"kev_cves": vuln["kev_cves"],
                            "distinct_cves": vuln["distinct_cves"]},
        "compatibility": {"eligible_total": compat["eligible_total"],
                          "cohorts": len(compat["cohorts"])},
        "dependency": {"nodes": dependency["nodes"], "edges": dependency["edges"]},
        "risk_distribution": risk["distribution"],
        "exclusion_reasons": reasons,
    }


def plan_campaign(db: Session, campaign: Campaign) -> dict:
    """DIAGNOSED -> PLANNED with persisted ring plans."""
    patch_row, endpoints, states_by_ep = load_world(db, campaign.patch_id)
    inv = make_investigation(db, topic=f"Rollout plan for {campaign.patch_id}",
                             campaign_id=campaign.id)
    output = PlanningAgent().run(db, inv, campaign, patch_row, endpoints,
                                 states_by_ep, sequence=6)
    transition(db, campaign, "PLANNED")
    return output


def request_start(db: Session, campaign: Campaign,
                  reason: str = "") -> Approval:
    """PLANNED -> AWAITING_APPROVAL; creates the deployment approval record."""
    pending = db.scalar(select(Approval).where(
        Approval.campaign_id == campaign.id, Approval.status == "pending"))
    if pending is not None:
        raise WorkflowViolation("a pending approval already exists for this campaign")
    transition(db, campaign, "AWAITING_APPROVAL",
               note="execution gate: human approval required")
    approval = Approval(
        campaign_id=campaign.id, approval_type="deployment", status="pending",
        requested_reason=reason or f"Deploy {campaign.patch_id} via staged rings",
    )
    db.add(approval)
    db.flush()
    return approval


def request_emergency_override(db: Session, campaign: Campaign,
                               reason: str = "") -> Approval:
    """Emergency fast-track: separate approval record type. Only valid from
    PLANNED/AWAITING_APPROVAL/FAILED states."""
    if campaign.emergency_approved:
        raise WorkflowViolation("emergency override already granted")
    if campaign.status not in ("PLANNED", "AWAITING_APPROVAL"):
        raise WorkflowViolation(
            f"emergency override not available from {campaign.status}")
    approval = Approval(
        campaign_id=campaign.id, approval_type="emergency_override",
        status="pending",
        requested_reason=reason or "EMERGENCY: exploited CVE requires fast-track rollout "
                                  "with critical-tier devices in early rings",
    )
    db.add(approval)
    db.flush()
    add_event(db, campaign.id, "emergency_override_requested",
              approval.requested_reason)
    return approval


def _replan_without_transition(db: Session, campaign: Campaign) -> None:
    """Re-run the planner in place (used by the emergency fast-track)."""
    from sqlalchemy import delete as _delete

    from app.agents.planning_agent import PlanningAgent
    from app.agents.base import make_investigation
    from app.models import RingPlan
    # No ring has executed yet (override is only available pre-execution), so
    # replace the stale plans instead of stacking a second set on top.
    db.execute(_delete(RingPlan).where(RingPlan.campaign_id == campaign.id))
    db.flush()
    patch_row, endpoints, states_by_ep = load_world(db, campaign.patch_id)
    inv = make_investigation(db, topic=f"Emergency replan {campaign.patch_id}",
                             campaign_id=campaign.id)
    PlanningAgent().run(db, inv, campaign, patch_row, endpoints,
                        states_by_ep, sequence=6)


def approve(db: Session, approval: Approval, decided_by: str = "operator",
            note: str = "") -> Campaign:
    if approval.status != "pending":
        raise WorkflowViolation(f"approval already {approval.status}")
    approval.status = "approved"
    approval.decided_by = decided_by
    approval.decision_note = note
    approval.decided_at = utcnow()
    campaign = db.get(Campaign, approval.campaign_id)
    if approval.approval_type == "emergency_override":
        # Grant override, re-plan so critical-tier devices may enter early rings,
        # and mark the deployment gate satisfied.
        campaign.emergency_approved = True
        _replan_without_transition(db, campaign)
        if campaign.status == "PLANNED":
            transition(db, campaign, "AWAITING_APPROVAL",
                       note="emergency override granted")
        transition(db, campaign, "APPROVED", note="emergency fast-track approved")
    else:
        transition(db, campaign, "APPROVED", note=note or "deployment approved")
    add_event(db, campaign.id, "approval_granted",
              f"{approval.approval_type} approved by {decided_by}")
    return campaign


def reject(db: Session, approval: Approval, decided_by: str = "operator",
           note: str = "") -> Campaign:
    if approval.status != "pending":
        raise WorkflowViolation(f"approval already {approval.status}")
    approval.status = "rejected"
    approval.decided_by = decided_by
    approval.decision_note = note or "rejected"
    approval.decided_at = utcnow()
    campaign = db.get(Campaign, approval.campaign_id)
    UNSAFE_PREVENTIONS_TOTAL.labels("approval_rejected").inc()
    if campaign.status == "AWAITING_APPROVAL":
        transition(db, campaign, "PLANNED", note="approval rejected")
    campaign.blocked_reason = (
        f"deployment rejected by {decided_by}: {approval.decision_note}"
    )
    add_event(db, campaign.id, "approval_rejected",
              campaign.blocked_reason)
    return campaign


# ------------------------------------------------------------------- execution

def advance(db: Session, campaign: Campaign) -> dict:
    """Execute the next ring; runs RCA on halt; completes after final ring.

    Gate: requires an APPROVED deployment (or emergency-approved campaign).
    """
    if campaign.blocked_reason and not campaign.emergency_approved:
        raise PermissionError(f"campaign blocked: {campaign.blocked_reason}")

    latest_deployment = db.scalars(select(Approval).where(
        Approval.campaign_id == campaign.id)).all()
    has_approved_gate = campaign.status == "APPROVED" or any(
        a.approval_type == "deployment" and a.status == "approved"
        for a in latest_deployment
    )
    if not has_approved_gate:
        raise PermissionError("campaign execution requires an APPROVED deployment")

    plan = next_pending_ring(db, campaign)
    if plan is None:
        raise WorkflowViolation("no pending ring to execute")

    patch_row, _endpoints, _states = load_world(db, campaign.patch_id)
    if campaign.status == "APPROVED":
        transition(db, campaign, "EXECUTING")
    result = execute_ring(db, campaign, plan.ring)

    response: dict = {"ring_execution": result}

    if result["stop_triggered"]:
        # AUTONOMOUS STOP: RCA -> recommendations; campaign FAILED.
        inv = make_investigation(db, topic=f"RCA halt {campaign.patch_id} @ {plan.ring}",
                                 campaign_id=campaign.id)
        rca_output = RcaAgent().run(db, inv, campaign, plan.ring, patch_row, sequence=7)
        ValidationAgent().run(db, inv, campaign.id, plan.ring, sequence=9)
        response["rca"] = rca_output
        return response

    # Clean ring -> VERIFYING then either next ring or completion.
    transition(db, campaign, "VERIFYING", note=f"{plan.ring} validated")
    nxt = next_pending_ring(db, campaign)
    if nxt is None:
        final = complete_campaign(db, campaign)
        response["completed"] = final
    else:
        transition(db, campaign, "EXECUTING",
                   note=f"advancing to {nxt.ring}")
        response["next_ring"] = nxt.ring
    return response


def run_rollback(db: Session, campaign: Campaign, rings: list[str] | None = None) -> dict:
    """FAILED -> ROLLED_BACK (or targeted rollback of specific executed rings)."""
    if campaign.status not in ("FAILED",):
        raise WorkflowViolation(f"rollback requires FAILED campaign, got {campaign.status}")
    executed_rings = [
        ex.ring for ex in db.scalars(select(RingExecution).where(
            RingExecution.campaign_id == campaign.id)).all()
        if ex.status in ("halted", "succeeded")
    ]
    target_rings = rings or executed_rings
    if not target_rings:
        raise WorkflowViolation("no executed rings to roll back")
    transition(db, campaign, "ROLLED_BACK")
    inv = make_investigation(db, topic=f"Rollback {campaign.patch_id}",
                             campaign_id=campaign.id)
    patch_row, _e, _s = load_world(db, campaign.patch_id)
    output = RollbackAgent().run(db, inv, campaign, sorted(target_rings), sequence=8)
    return output
