"""Simulator seed + fleet + vulnerabilities + compatibility routes."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.compatibility_agent import matrix_cells_detailed
from app.agents.inventory_agent import fleet_stats
from app.agents.vulnerability_agent import exposure_view
from app.db import get_db
from app.engine.applicability import build_cohorts
from app.engine.rollout_engine import load_world
from app.engine.detectors import run_all_detectors, sort_findings
from app.models import Endpoint, Patch
from app.schemas import (
    CompatibilityMatrix, EndpointDetailOut, EndpointOut, FleetSummary,
    PatchOut, SeedRequest, SeedResult,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


@router.post("/simulator/seed", response_model=SeedResult)
def seed(request: SeedRequest | None = None, db: Session = Depends(get_db)):
    from simulator import seed_world
    body = request or SeedRequest()
    try:
        result = seed_world(db, estate_size=body.estate_size)
        db.commit()
    except Exception as exc:
        logger.exception("seed failed")
        raise HTTPException(status_code=500, detail="seeding failed") from exc
    return SeedResult(**result)


def _endpoint_or_404(db: Session, endpoint_id: int) -> Endpoint:
    ep = db.get(Endpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="endpoint not found")
    return ep


@router.get("/fleet/summary", response_model=FleetSummary)
def fleet_summary(db: Session = Depends(get_db)):
    endpoints = db.scalars(select(Endpoint)).all()
    stats = fleet_stats(endpoints)
    return FleetSummary(
        total_endpoints=stats["total_endpoints"],
        by_os=stats["by_os"],
        by_department=stats["by_department"],
        by_criticality=stats["by_criticality"],
        eol_count=stats["eol_count"],
        pending_reboot_over_30d=stats["pending_reboot_over_30d"],
        avg_health=stats["avg_health"],
        avg_disk_free_gb=stats["avg_disk_free_gb"],
    )


@router.get("/fleet/endpoints", response_model=list[EndpointOut])
def list_endpoints(
    department: str | None = None,
    os: str | None = Query(default=None, alias="os"),
    criticality: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    role: str | None = None,
    eol: bool | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = select(Endpoint).order_by(Endpoint.id)
    if department:
        query = query.where(Endpoint.department == department)
    if os:
        query = query.where(Endpoint.os == os)
    if criticality:
        query = query.where(Endpoint.criticality == criticality)
    if role:
        query = query.where(Endpoint.role == role)
    if eol is not None:
        query = query.where(Endpoint.eol == eol)
    rows = db.scalars(query.offset(offset).limit(limit)).all()
    return [EndpointOut(**{k: getattr(e, k) for k in EndpointOut.model_fields}) for e in rows]


@router.get("/fleet/endpoints/{endpoint_id}", response_model=EndpointDetailOut)
def endpoint_detail(endpoint_id: int, db: Session = Depends(get_db)):
    ep = _endpoint_or_404(db, endpoint_id)
    data = {k: getattr(ep, k) for k in EndpointOut.model_fields}
    data.update({
        "patch_states": [
            {"patch_id": s.patch_id, "state": s.state} for s in ep.patch_states],
        "findings": [
            {"cve_id": f.cve_id, "patch_id": f.patch_id, "cvss": f.cvss,
             "known_exploited": f.known_exploited, "status": f.status}
            for f in ep.findings],
    })
    return EndpointDetailOut(**data)


@router.get("/vulnerabilities")
def vulnerabilities(db: Session = Depends(get_db)):
    """Exploitability-first open exposure groups."""
    vulns = exposure_view(db)
    total_affected = sum(v["affected_endpoints"] for v in vulns)
    kev = [v for v in vulns if v["known_exploited"]]
    return {
        "summary": {
            "distinct_cves": len(vulns),
            "kev_cves": len(kev),
            "endpoint_exposures_total": total_affected,
            "kev_endpoint_exposures": sum(v["affected_endpoints"] for v in kev),
        },
        "groups": vulns[:50],
    }


@router.get("/detections")
def detections(db: Session = Depends(get_db)):
    """All deterministic detector outputs (exploitable-first ordering)."""
    findings = sort_findings(run_all_detectors(db))
    return {"count": len(findings), "findings": findings}


@router.get("/catalog", response_model=list[PatchOut])
def patch_catalog(db: Session = Depends(get_db)):
    """Full simulated patch catalog including CVEs and public known issues."""
    rows = db.scalars(select(Patch).order_by(Patch.patch_id)).all()
    out = []
    for p in rows:
        out.append(PatchOut(**{
            "patch_id": p.patch_id, "name": p.name, "target_os": p.target_os,
            "severity": p.severity, "reboot_required": p.reboot_required,
            "release_date": p.release_date,
            "typical_install_minutes": p.typical_install_minutes,
            "disk_space_required_mb": p.disk_space_required_mb,
            "supersedes": p.supersedes or [], "prerequisites": p.prerequisites or [],
            "superseded_by": p.superseded_by,
            "at_risk_policy_default": p.at_risk_policy_default,
            "notes": p.notes or "",
            "cves": [{"cve_id": c.cve_id, "cvss": c.cvss,
                      "known_exploited": c.known_exploited,
                      "description": getattr(c, "description", "") or ""}
                     for c in p.cves],
            "known_issues": [{"kind": k.kind, "app_name": k.app_name,
                              "version_below": k.version_below,
                              "failure_class": k.failure_class,
                              "description": k.description or ""}
                             for k in p.known_issues],
        }))
    return out


@router.get("/compatibility/{patch_id}", response_model=CompatibilityMatrix)
def compatibility(patch_id: str, at_risk_policy: str = Query(
        default="canary_prove", pattern="^(canary_prove|exclude)$"),
        db: Session = Depends(get_db)):
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == patch_id))
    if patch_row is None:
        raise HTTPException(status_code=404, detail="unknown patch")
    _patch, endpoints, states_by_ep = load_world(db, patch_id)
    cells = matrix_cells_detailed(patch_row, endpoints, states_by_ep, at_risk_policy)
    cohorts = [v for _k, v in sorted(build_cohorts(endpoints, patch_row).items())]
    eligible_total = sum(c["applicable"] + c["at_risk"] for c in cells)
    return CompatibilityMatrix(
        patch_id=patch_id, eligible_total=eligible_total,
        cells=[{"department": c["department"], "os": c["os"], **{
            k: c[k] for k in ("total", "applicable", "incompatible", "at_risk",
                              "blocked_disk", "missing_prereq")}} for c in cells],
        cohorts=cohorts,
    )
