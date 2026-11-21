"""The agent tool surface: 12 registered, allow-listed, audited tools.
No shell/subprocess/file tools exist. High-risk tools are approval-gated."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.engine import validation as validation_mod
from app.engine.dependencies import dependents_count, build_dependency_graph
from app.engine.risk_engine import assess_endpoint_patch
from app.engine.rollout_engine import (
    compute_eligibility, execute_ring, get_plan_for, load_world,
)
from app.engine.rca import classify_failures
from app.agents.rca_agent import collect_ring_failures
from app.models import (
    Action, Approval, Campaign, DeviceInstallResult, Endpoint, Patch,
    RingExecution, Validation,
)
from app.tools.base import ToolError, ToolPermissionError, ToolSpec
from app.workflow import engine as wf

MAX_PAGE = 500


# ------------------------------------------------------------------ handlers

def _tool_query_fleet(db: Session, args: dict) -> dict:
    query = select(Endpoint)
    for field in ("department", "os", "criticality", "role"):
        if args.get(field):
            query = query.where(getattr(Endpoint, field) == args[field])
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(
        query.order_by(Endpoint.id).offset(args.get("offset", 0))
        .limit(args.get("limit", 50))
    ).all()
    return {
        "total": total,
        "count": len(rows),
        "endpoints": [
            {"id": e.id, "hostname": e.hostname, "os": e.os, "role": e.role,
             "department": e.department, "criticality": e.criticality,
             "health_score": e.health_score, "eol": e.eol}
            for e in rows
        ],
    }


def _resolve_endpoint(db: Session, args: dict):
    ep = None
    if args.get("endpoint_id") is not None:
        ep = db.get(Endpoint, args["endpoint_id"])
    elif args.get("hostname"):
        ep = db.scalar(select(Endpoint).where(Endpoint.hostname == args["hostname"]))
    if ep is None:
        raise ToolError("endpoint not found")
    return ep


def _tool_get_endpoint_detail(db: Session, args: dict) -> dict:
    ep = _resolve_endpoint(db, args)
    return {
        "id": ep.id, "hostname": ep.hostname, "os": ep.os, "os_build": ep.os_build,
        "role": ep.role, "department": ep.department, "criticality": ep.criticality,
        "eol": ep.eol, "disk_free_gb": ep.disk_free_gb, "ram_gb": ep.ram_gb,
        "cpu_age_years": ep.cpu_age_years, "health_score": ep.health_score,
        "historical_patch_failures": ep.historical_patch_failures,
        "pending_reboot_days": ep.pending_reboot_days,
        "compliance_flags": ep.compliance_flags, "software": ep.software,
        "patch_states": [
            {"patch_id": s.patch_id, "state": s.state} for s in ep.patch_states
        ],
        "open_findings": [
            {"cve_id": f.cve_id, "patch_id": f.patch_id, "cvss": f.cvss,
             "known_exploited": f.known_exploited}
            for f in ep.findings if f.status == "open"
        ],
    }


def _tool_query_patch_catalog(db: Session, args: dict) -> dict:
    query = select(Patch)
    if args.get("patch_id"):
        query = query.where(Patch.patch_id == args["patch_id"])
    if args.get("target_os"):
        query = query.where(Patch.target_os == args["target_os"])
    if args.get("severity"):
        query = query.where(Patch.severity == args["severity"])
    rows = db.scalars(query.order_by(Patch.patch_id)).all()
    return {
        "count": len(rows),
        "patches": [
            {"patch_id": p.patch_id, "name": p.name, "target_os": p.target_os,
             "severity": p.severity, "reboot_required": p.reboot_required,
             "release_date": p.release_date.isoformat(),
             "known_exploited": any(c.known_exploited for c in p.cves),
             "known_issues": [
                 {"app_name": i.app_name, "version_below": i.version_below,
                  "failure_class": i.failure_class} for i in p.known_issues],
             "supersedes": p.supersedes, "prerequisites": p.prerequisites}
            for p in rows
        ],
    }


def _tool_compute_patch_risk(db: Session, args: dict) -> dict:
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == args["patch_id"]))
    if patch_row is None:
        raise ToolError(f"unknown patch {args['patch_id']}")
    endpoints = db.scalars(select(Endpoint)).all()
    graph = build_dependency_graph(endpoints)
    if args.get("department"):
        endpoints = [e for e in endpoints if e.department == args["department"]]
    if args.get("endpoint_ids"):
        wanted = set(args["endpoint_ids"])
        endpoints = [e for e in endpoints if e.id in wanted]
    endpoints = endpoints[:200]
    results = [
        assess_endpoint_patch(e, patch_row, dependents_count(graph, e.id))
        for e in endpoints
    ]
    dist: dict[str, int] = {}
    for r in results:
        dist[r["bucket"]] = dist.get(r["bucket"], 0) + 1
    return {"assessed": len(results), "distribution": dist,
            "assessments": results[:50]}


def _get_campaign(db: Session, campaign_id: int) -> Campaign:
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise ToolError(f"campaign {campaign_id} not found")
    return campaign


def _tool_plan_rollout(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    if campaign.status not in ("DIAGNOSED", "PLANNED", "ROLLED_BACK", "FAILED"):
        raise ToolError(f"cannot plan from status {campaign.status}")
    output = wf.plan_campaign(db, campaign)
    db.commit()
    return output


def _tool_start_campaign(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    if campaign.status != "PLANNED":
        raise ToolError(f"start requires PLANNED campaign, got {campaign.status}")
    approval = wf.request_start(db, campaign, args.get("reason", ""))
    db.commit()
    return {
        "campaign_status": campaign.status,
        "approval": {"id": approval.id, "type": approval.approval_type,
                     "status": approval.status},
        "note": "execution paused at AWAITING_APPROVAL",
    }


def _require_execution_gate(db: Session, campaign: Campaign) -> None:
    approvals = db.scalars(select(Approval).where(
        Approval.campaign_id == campaign.id)).all()
    approved = any(a.status == "approved" and a.approval_type in
                   ("deployment", "emergency_override") for a in approvals)
    pending = any(a.status == "pending" for a in approvals)
    if pending and not approved:
        raise ToolPermissionError(
            "execution blocked: deployment approval is pending (AWAITING_APPROVAL)")
    if not approved:
        raise ToolPermissionError(
            "execution blocked: no approved deployment record")
    if campaign.blocked_reason and not campaign.emergency_approved:
        raise ToolPermissionError(f"campaign blocked: {campaign.blocked_reason}")


def _tool_advance_ring(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    if campaign.status not in ("APPROVED", "EXECUTING", "VERIFYING"):
        # Distinguish gate refusal from state error for clearer audits.
        _require_execution_gate(db, campaign)
        raise ToolError(f"cannot advance ring from status {campaign.status}")
    _require_execution_gate(db, campaign)
    result = wf.advance(db, campaign)
    db.commit()
    return result


def _tool_check_ring_health(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    execs = db.scalars(select(RingExecution).where(
        RingExecution.campaign_id == campaign.id).order_by(RingExecution.position)).all()
    if args.get("ring"):
        execs = [ex for ex in execs if ex.ring == args["ring"]]
    vals = db.scalars(select(Validation).where(
        Validation.campaign_id == campaign.id)).all()
    pass_rate = (sum(1 for v in vals if v.passed) / len(vals)) if vals else None
    return {
        "rings": [
            {"ring": ex.ring, "status": ex.status, "device_count": ex.device_count,
             "failure_rate": ex.failure_rate, "threshold": ex.threshold,
             "stop_triggered": ex.stop_triggered} for ex in execs
        ],
        "validation_pass_rate": round(pass_rate, 4) if pass_rate is not None else None,
    }


def _tool_classify_failures(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    failures = collect_ring_failures(db, campaign.id, args.get("ring"))
    counts = classify_failures(
        [{"failure_class": f.failure_class, "error_detail": f.error_detail}
         for f in failures])
    return {"failure_classes": counts, "total_failures": len(failures),
            "ring": args.get("ring", "all")}


def _tool_rollback_ring(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    rings = args.get("rings")
    result = wf.run_rollback(db, campaign, rings)
    db.commit()
    return result


def _tool_validate_endpoint_post_patch(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    ep = _resolve_endpoint(db, args)
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == campaign.patch_id))
    install = db.scalar(select(DeviceInstallResult).where(
        DeviceInstallResult.campaign_id == campaign.id,
        DeviceInstallResult.endpoint_id == ep.id))
    sim = ({"outcome": install.outcome, "failure_class": install.failure_class}
           if install else {"outcome": "success", "failure_class": None})
    val = validation_mod.validate_endpoint_post_patch(ep, patch_row, sim, rebooted=True)
    return {"endpoint_id": ep.id, **val}


def _tool_exclude_endpoints(db: Session, args: dict) -> dict:
    campaign = _get_campaign(db, args["campaign_id"])
    if campaign.status in ("EXECUTING", "VERIFYING", "COMPLETED"):
        raise ToolError(f"cannot exclude mid-flight from status {campaign.status}")
    ids = list(dict.fromkeys(args["endpoint_ids"]))
    known = {e.id for e in db.scalars(
        select(Endpoint.id).where(Endpoint.id.in_(ids))).all()}
    unknown = sorted(set(ids) - known)
    current = list(campaign.excluded_endpoint_ids or [])
    added = [i for i in ids if i not in current]
    campaign.excluded_endpoint_ids = current + added
    reasons = dict(campaign.exclusion_reasons or {})
    reasons[args.get("reason", "operator_exclusion")] = \
        reasons.get(args.get("reason", "operator_exclusion"), 0) + len(added)
    campaign.exclusion_reasons = reasons
    db.add(Action(campaign_id=campaign.id, action_type="exclude_endpoints",
                  target={"endpoint_ids": added}, status="executed",
                  reason=args.get("reason", "operator exclusion")))
    db.commit()
    return {"added": added, "unknown_ids": unknown,
            "total_excluded": len(campaign.excluded_endpoint_ids)}


# ------------------------------------------------------------------- registry

def build_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="query_fleet",
            purpose="List/filter fleet endpoints with pagination.",
            input_schema={
                "type": "object",
                "properties": {
                    "department": {"type": "string"}, "os": {"type": "string"},
                    "criticality": {"type": "string",
                                    "enum": ["critical", "high", "medium", "low"]},
                    "role": {"type": "string"},
                    "limit": {"type": "integer"}, "offset": {"type": "integer"},
                },
            },
            permission="agent", risk_level="read", timeout_s=10,
            handler=_tool_query_fleet,
        ),
        ToolSpec(
            name="get_endpoint_detail",
            purpose="Full detail for one endpoint incl. software + findings.",
            input_schema={"type": "object",
                          "properties": {"endpoint_id": {"type": "integer"},
                                         "hostname": {"type": "string"}}},
            permission="agent", risk_level="read", timeout_s=10,
            handler=_tool_get_endpoint_detail,
        ),
        ToolSpec(
            name="query_patch_catalog",
            purpose="Query the patch catalog with CVEs/known issues.",
            input_schema={"type": "object",
                          "properties": {"patch_id": {"type": "string"},
                                         "target_os": {"type": "string"},
                                         "severity": {"type": "string"}}},
            permission="agent", risk_level="read", timeout_s=10,
            handler=_tool_query_patch_catalog,
        ),
        ToolSpec(
            name="compute_patch_risk",
            purpose="Deterministic weighted risk scores for endpoint x patch.",
            input_schema={"type": "object", "required": ["patch_id"],
                          "properties": {"patch_id": {"type": "string"},
                                         "department": {"type": "string"},
                                         "endpoint_ids": {"type": "array"}}},
            permission="agent", risk_level="read", timeout_s=30,
            handler=_tool_compute_patch_risk,
        ),
        ToolSpec(
            name="plan_rollout",
            purpose="Assign eligible endpoints to rollout rings for a campaign.",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"}}},
            permission="agent", risk_level="write", timeout_s=60,
            handler=_tool_plan_rollout,
        ),
        ToolSpec(
            name="start_campaign",
            purpose="Request execution start; pauses at AWAITING_APPROVAL.",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"},
                                         "reason": {"type": "string"}}},
            permission="human-approval", risk_level="high", timeout_s=30,
            handler=_tool_start_campaign,
        ),
        ToolSpec(
            name="advance_ring",
            purpose="Execute the next rollout ring (approval-gated; may halt).",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"}}},
            permission="human-approval", risk_level="high", timeout_s=300,
            handler=_tool_advance_ring,
        ),
        ToolSpec(
            name="check_ring_health",
            purpose="Ring execution status + validation pass rates.",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"},
                                         "ring": {"type": "string"}}},
            permission="agent", risk_level="read", timeout_s=15,
            handler=_tool_check_ring_health,
        ),
        ToolSpec(
            name="classify_failures",
            purpose="Taxonomy classification of failed installs.",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"},
                                         "ring": {"type": "string"}}},
            permission="agent", risk_level="read", timeout_s=15,
            handler=_tool_classify_failures,
        ),
        ToolSpec(
            name="rollback_ring",
            purpose="Roll back executed ring(s) to pre-campaign patch state.",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"},
                                         "rings": {"type": "array"}}},
            permission="human-approval", risk_level="high", timeout_s=120,
            handler=_tool_rollback_ring,
        ),
        ToolSpec(
            name="validate_endpoint_post_patch",
            purpose="Re-run the post-patch validation sequence for one device.",
            input_schema={"type": "object", "required": ["campaign_id"],
                          "properties": {"campaign_id": {"type": "integer"},
                                         "endpoint_id": {"type": "integer"},
                                         "hostname": {"type": "string"}}},
            permission="agent", risk_level="read", timeout_s=15,
            handler=_tool_validate_endpoint_post_patch,
        ),
        ToolSpec(
            name="exclude_endpoints",
            purpose="Exclude endpoint ids from a planned campaign.",
            input_schema={"type": "object",
                          "required": ["campaign_id", "endpoint_ids"],
                          "properties": {"campaign_id": {"type": "integer"},
                                         "endpoint_ids": {"type": "array"},
                                         "reason": {"type": "string"}}},
            permission="agent", risk_level="write", timeout_s=15,
            handler=_tool_exclude_endpoints,
        ),
    ]
