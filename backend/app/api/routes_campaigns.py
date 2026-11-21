"""Campaigns, approvals, rings, failures/RCA, rollbacks, events routes."""
from __future__ import annotations

import logging
from functools import wraps

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.engine.rca import correlate_root_cause
from app.agents.rca_agent import collect_ring_failures
from app.models import (
    Action, Approval, Campaign, DeviceInstallResult, Endpoint,
    Investigation, Outcome, RingExecution, RingPlan, RiskAssessment,
    Rollback, Validation, Event,
)
from app.schemas import (
    ApprovalOut, CampaignCreate, CampaignOut, DeviceInstallResultOut,
    EventOut, RCARecordOut, RingExecutionOut, RingPlanOut, RollbackOut,
    ValidationOut,
)
from app.tools.base import ToolError, ToolPermissionError
from app.workflow import engine as wf
from app.workflow.engine import WorkflowViolation

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


def _campaign_or_404(db: Session, campaign_id: int) -> Campaign:
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="campaign not found")
    return campaign


def _map_tool_errors(fn):
    @wraps(fn)  # preserve the signature FastAPI introspects for routing
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except WorkflowViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ToolError, ToolPermissionError, PermissionError) as exc:
            status = 403 if isinstance(exc, (ToolPermissionError, PermissionError)) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return wrapped


@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(limit: int = Query(default=50, ge=1, le=200),
                   db: Session = Depends(get_db)):
    rows = db.scalars(select(Campaign).order_by(Campaign.id.desc()).limit(limit)).all()
    return [CampaignOut(**{k: getattr(c, k) for k in CampaignOut.model_fields})
            for c in rows]


@router.post("/campaigns", response_model=CampaignOut, status_code=201)
def create_campaign(body: CampaignCreate, db: Session = Depends(get_db)):
    try:
        campaign = wf.create_campaign(db, body.patch_id, body.name,
                                      body.at_risk_policy)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    investigation = wf.run_investigation(db, campaign)
    db.commit()
    return _campaign_or_404(db, campaign.id)


@router.post("/campaigns/{campaign_id}/investigate")
def investigate(campaign_id: int, db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    if campaign.status != "DETECTED":
        raise HTTPException(status_code=409,
                            detail=f"investigation already ran (status {campaign.status})")
    result = wf.run_investigation(db, campaign)
    db.commit()
    return result


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    return _campaign_or_404(db, campaign_id)


@router.delete("/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    if campaign.status in ("EXECUTING", "VERIFYING"):
        raise HTTPException(status_code=409,
                            detail="cannot delete a campaign mid-execution")
    db.delete(campaign)
    db.commit()
    return {"deleted": campaign_id}


@router.post("/campaigns/{campaign_id}/plan")
@_map_tool_errors
def plan(campaign_id: int, db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    output = wf.plan_campaign(db, campaign)
    db.commit()
    return output


@router.post("/campaigns/{campaign_id}/start")
@_map_tool_errors
def start(campaign_id: int, reason: str = "", db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    approval = wf.request_start(db, campaign, reason)
    db.commit()
    return {"approval": ApprovalOut(**{k: getattr(approval, k)
                                        for k in ApprovalOut.model_fields}),
            "campaign_status": campaign.status}


@router.post("/campaigns/{campaign_id}/emergency-override")
@_map_tool_errors
def emergency_override(campaign_id: int, reason: str = "",
                       db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    approval = wf.request_emergency_override(db, campaign, reason)
    db.commit()
    return {"approval": ApprovalOut(**{k: getattr(approval, k)
                                        for k in ApprovalOut.model_fields}),
            "note": "emergency fast-track requires its own approval"}


@router.post("/campaigns/{campaign_id}/advance")
@_map_tool_errors
def advance_ring(campaign_id: int, db: Session = Depends(get_db)):
    """Execute the next ring; autonomous stop conditions may halt the campaign."""
    campaign = _campaign_or_404(db, campaign_id)
    result = wf.advance(db, campaign)
    # Persist a metrics snapshot after each ring for the trend panel.
    from app.metrics_kpi import compute_summary, persist_snapshot
    persist_snapshot(db, compute_summary(db), campaign_id=campaign.id)
    db.commit()
    return result


@router.post("/campaigns/{campaign_id}/rollback")
@_map_tool_errors
def rollback(campaign_id: int, rings: list[str] | None = None,
             db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    result = wf.run_rollback(db, campaign, rings)
    db.commit()
    return result


# ------------------------------------------------------------------ approvals

@router.get("/approvals", response_model=list[ApprovalOut])
def approvals(status: str | None = Query(default=None, pattern="^(pending|approved|rejected)$"),
              db: Session = Depends(get_db)):
    query = select(Approval).order_by(Approval.id.desc())
    if status:
        query = query.where(Approval.status == status)
    rows = db.scalars(query.limit(200)).all()
    return [ApprovalOut(**{k: getattr(a, k) for k in ApprovalOut.model_fields})
            for a in rows]


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalOut)
@_map_tool_errors
def approve(approval_id: int, decided_by: str = "operator", note: str = "",
            db: Session = Depends(get_db)):
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    campaign = wf.approve(db, approval, decided_by, note)
    db.commit()
    return ApprovalOut(**{k: getattr(approval, k) for k in ApprovalOut.model_fields})


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalOut)
@_map_tool_errors
def reject(approval_id: int, decided_by: str = "operator", note: str = "",
           db: Session = Depends(get_db)):
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    campaign = wf.reject(db, approval, decided_by, note)
    db.commit()
    return ApprovalOut(**{k: getattr(approval, k) for k in ApprovalOut.model_fields})


# -------------------------------------------------------------- rings/results

@router.get("/campaigns/{campaign_id}/rings", response_model=list[RingPlanOut])
def ring_plans(campaign_id: int, include_ids: bool = False,
               db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    plans = db.scalars(select(RingPlan).where(
        RingPlan.campaign_id == campaign_id).order_by(RingPlan.position)).all()
    return [
        RingPlanOut(
            ring=p.ring, position=p.position, size=p.size, threshold=p.threshold,
            criteria_note=p.criteria_note,
            endpoint_ids=(p.endpoint_ids or []) if include_ids else [],
        ) for p in plans
    ]


@router.get("/campaigns/{campaign_id}/executions", response_model=list[RingExecutionOut])
def ring_executions(campaign_id: int, db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    execs = db.scalars(select(RingExecution).where(
        RingExecution.campaign_id == campaign_id).order_by(RingExecution.position)).all()
    return [RingExecutionOut(**{k: getattr(ex, k)
                                for k in RingExecutionOut.model_fields}) for ex in execs]


@router.get("/campaigns/{campaign_id}/results", response_model=list[DeviceInstallResultOut])
def install_results(campaign_id: int, ring: str | None = None,
                    outcome: str | None = Query(default=None, pattern="^(success|pending_reboot|failed|rolled_back)$"),
                    limit: int = Query(default=100, ge=1, le=500),
                    db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    query = select(DeviceInstallResult).where(
        DeviceInstallResult.campaign_id == campaign_id)
    if ring:
        query = query.where(DeviceInstallResult.ring == ring)
    if outcome:
        query = query.where(DeviceInstallResult.outcome == outcome)
    rows = db.scalars(query.order_by(DeviceInstallResult.id).limit(limit)).all()
    hostnames = {}
    ids = [r.endpoint_id for r in rows]
    if ids:
        hostnames = {e.id: e.hostname for e in db.scalars(
            select(Endpoint).where(Endpoint.id.in_(ids))).all()}
    return [
        DeviceInstallResultOut(
            endpoint_id=r.endpoint_id, hostname=hostnames.get(r.endpoint_id),
            ring=r.ring, outcome=r.outcome, failure_class=r.failure_class,
            attempts=r.attempts, install_seconds=r.install_seconds,
            error_detail=r.error_detail,
        ) for r in rows
    ]


@router.get("/campaigns/{campaign_id}/validations", response_model=list[ValidationOut])
def validations(campaign_id: int, phase: str | None = Query(
        default=None, pattern="^(post_patch|post_rollback)$"),
        db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    query = select(Validation).where(Validation.campaign_id == campaign_id)
    if phase:
        query = query.where(Validation.phase == phase)
    rows = db.scalars(query.order_by(Validation.id).limit(500)).all()
    return [ValidationOut(**{k: getattr(v, k) for k in ValidationOut.model_fields})
            for v in rows]


# ------------------------------------------------------------------ RCA et al

@router.get("/campaigns/{campaign_id}/failures")
def failures(campaign_id: int, db: Session = Depends(get_db)):
    campaign = _campaign_or_404(db, campaign_id)
    all_failures = collect_ring_failures(db, campaign.id)
    counts: dict[str, int] = {}
    for f in all_failures:
        counts[f.failure_class or "unknown"] = counts.get(f.failure_class or "unknown", 0) + 1
    failed_rows = [{"failure_class": f.failure_class, "error_detail": f.error_detail}
                   for f in all_failures]
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == campaign.patch_id))
    hypotheses = []
    if failed_rows and patch_row is not None:
        endpoints = db.scalars(select(Endpoint)).all()
        ep_map = {e.id: e for e in endpoints}
        failed_eps = [ep_map[r.endpoint_id] for r in all_failures
                      if r.endpoint_id in ep_map]
        ok_rows = db.scalars(select(DeviceInstallResult).where(
            DeviceInstallResult.campaign_id == campaign_id,
            DeviceInstallResult.outcome.in_(("success", "pending_reboot")))).all()
        ok_eps = [ep_map[r.endpoint_id] for r in ok_rows if r.endpoint_id in ep_map]
        hypotheses = correlate_root_cause(failed_eps, ok_eps, patch_row)
    return {"total": len(all_failures), "classes": counts, "hypotheses": hypotheses}


@router.get("/campaigns/{campaign_id}/rca", response_model=list[RCARecordOut])
def rca_records(campaign_id: int, db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    from app.models import RCARecord
    rows = db.scalars(select(RCARecord).where(
        RCARecord.campaign_id == campaign_id)).all()
    return [RCARecordOut(**{k: getattr(r, k) for k in RCARecordOut.model_fields})
            for r in rows]


@router.get("/rollbacks", response_model=list[RollbackOut])
def rollbacks(campaign_id: int | None = None, db: Session = Depends(get_db)):
    query = select(Rollback).order_by(Rollback.id.desc()).limit(100)
    if campaign_id:
        query = query.where(Rollback.campaign_id == campaign_id)
    rows = db.scalars(query).all()
    return [RollbackOut(**{k: getattr(r, k) for k in RollbackOut.model_fields})
            for r in rows]


@router.get("/campaigns/{campaign_id}/events", response_model=list[EventOut])
def campaign_events(campaign_id: int, limit: int = Query(default=100, ge=1, le=500),
                    db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    rows = db.scalars(select(Event).where(Event.campaign_id == campaign_id)
                      .order_by(Event.id.desc()).limit(limit)).all()
    return [EventOut(**{k: getattr(e, k) for k in EventOut.model_fields}) for e in rows]


@router.get("/events", response_model=list[EventOut])
def all_events(limit: int = Query(default=100, ge=1, le=500),
               db: Session = Depends(get_db)):
    rows = db.scalars(select(Event).order_by(Event.id.desc()).limit(limit)).all()
    return [EventOut(**{k: getattr(e, k) for k in EventOut.model_fields}) for e in rows]


@router.get("/campaigns/{campaign_id}/investigations")
def investigations(campaign_id: int, db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    invs = db.scalars(select(Investigation).where(
        Investigation.campaign_id == campaign_id)).all()
    out = []
    for inv in invs:
        out.append({
            "id": inv.id, "topic": inv.topic, "stage": inv.stage,
            "summary": inv.summary,
            "stage_runs": [
                {"agent": s.agent, "sequence": s.sequence, "status": s.status,
                 "llm_mode": s.llm_mode, "duration_ms": s.duration_ms,
                 "output": s.output, "rationale": s.llm_rationale}
                for s in sorted(inv.stage_runs, key=lambda x: x.sequence)
            ],
            "decisions": [
                {"decision": d.decision, "confidence": d.confidence,
                 "risk_level": d.risk_level, "requires_approval": d.requires_approval}
                for d in inv.decisions
            ],
            "evidence_count": len(inv.evidence),
        })
    return out


@router.get("/campaigns/{campaign_id}/actions")
def actions(campaign_id: int, db: Session = Depends(get_db)):
    _campaign_or_404(db, campaign_id)
    rows = db.scalars(select(Action).where(Action.campaign_id == campaign_id)).all()
    return [
        {"id": a.id, "action_type": a.action_type, "target": a.target,
         "status": a.status, "reason": a.reason} for a in rows
    ]


@router.get("/outcomes")
def outcomes(campaign_id: int | None = None,
             limit: int = Query(default=200, ge=1, le=1000),
             db: Session = Depends(get_db)):
    query = select(Outcome).order_by(Outcome.id.desc()).limit(limit)
    if campaign_id:
        query = query.where(Outcome.campaign_id == campaign_id)
    rows = db.scalars(query).all()
    return [
        {"endpoint_id": o.endpoint_id, "patch_id": o.patch_id,
         "final_outcome": o.final_outcome, "detail": o.detail}
        for o in rows
    ]


@router.get("/risk-assessments")
def risk_assessments(campaign_id: int | None = None,
                     bucket: str | None = Query(default=None, pattern="^[P][1-4]$"),
                     limit: int = Query(default=50, ge=1, le=500),
                     db: Session = Depends(get_db)):
    query = select(RiskAssessment).order_by(RiskAssessment.score.desc()).limit(limit)
    if campaign_id:
        query = query.where(RiskAssessment.campaign_id == campaign_id)
    if bucket:
        query = query.where(RiskAssessment.bucket == bucket)
    rows = db.scalars(query).all()
    return [
        {"endpoint_id": r.endpoint_id, "patch_id": r.patch_id, "score": r.score,
         "bucket": r.bucket, "factor_values": r.factor_values}
        for r in rows
    ]
