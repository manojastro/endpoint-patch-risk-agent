"""Metrics summary, evaluation run, and tool-audit routes."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.evaluation import DEFAULT_GROUND_TRUTH, load_ground_truth, run_evaluation
from app.metrics_kpi import compute_summary, persist_snapshot, update_prometheus_gauges
from app.models import Endpoint, EvaluationRun, ToolCall
from app.schemas import EvaluationRunOut, MetricsSummary, ToolSpecOut
from app.tools.base import REGISTRY, register_all

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


@router.get("/metrics/summary", response_model=MetricsSummary)
def metrics_summary(persist: bool = False, db: Session = Depends(get_db)):
    try:
        summary = compute_summary(db)
        update_prometheus_gauges(summary, db)
        if persist:
            persist_snapshot(db, summary)
    except Exception as exc:
        logger.exception("metrics computation failed")
        raise HTTPException(status_code=500, detail="metrics computation failed") from exc
    return MetricsSummary(**summary)


@router.get("/metrics/snapshots")
def metric_snapshots(limit: int = Query(default=50, ge=1, le=500),
                     db: Session = Depends(get_db)):
    from app.models import MetricSnapshot
    rows = db.scalars(select(MetricSnapshot).order_by(
        MetricSnapshot.id.desc()).limit(limit)).all()
    return [
        {"id": r.id, "name": r.name, "value_json": r.value_json,
         "campaign_id": r.campaign_id, "created_at": r.created_at.isoformat()}
        for r in rows
    ]


@router.post("/evaluation/run", response_model=EvaluationRunOut)
def evaluation_run(estate_size: int = Query(default=800, ge=100, le=5000),
                   db: Session = Depends(get_db)):
    """Run all ground-truth scenarios in an isolated sandbox world."""
    result = run_evaluation(DEFAULT_GROUND_TRUTH, estate_size=estate_size)
    run_row = EvaluationRun(
        scenario_results=result["scenario_results"],
        passed_count=result["passed_count"], failed_count=result["failed_count"],
        total_checks=result["total_checks"], all_passed=result["all_passed"],
        duration_ms=result["duration_ms"],
    )
    db.add(run_row)
    db.commit()
    return EvaluationRunOut(id=run_row.id, **{
        k: result[k] for k in ("scenario_results", "passed_count", "failed_count",
                               "total_checks", "all_passed", "duration_ms")},
        created_at=run_row.created_at)


@router.get("/evaluation/ground-truth")
def ground_truth():
    return load_ground_truth()


@router.get("/evaluation/runs", response_model=list[EvaluationRunOut])
def evaluation_runs(limit: int = Query(default=10, ge=1, le=100),
                    db: Session = Depends(get_db)):
    rows = db.scalars(select(EvaluationRun).order_by(
        EvaluationRun.id.desc()).limit(limit)).all()
    return [EvaluationRunOut(**{k: getattr(r, k) for k in EvaluationRunOut.model_fields})
            for r in rows]


# ------------------------------------------------------------------ tools/audit

@router.get("/tools", response_model=list[ToolSpecOut])
def list_tools():
    register_all()
    return [ToolSpecOut(**spec) for spec in REGISTRY.list_specs()]


@router.get("/audit/tool-calls")
def tool_calls(limit: int = Query(default=100, ge=1, le=500),
               db: Session = Depends(get_db)):
    rows = db.scalars(select(ToolCall).order_by(
        ToolCall.id.desc()).limit(limit)).all()
    return [
        {"id": t.id, "tool_name": t.tool_name, "ok": t.ok, "error": t.error,
         "caller": t.caller, "risk_level": t.risk_level,
         "duration_ms": t.duration_ms, "arguments": t.arguments,
         "result_summary": t.result_summary[:200],
         "created_at": t.created_at.isoformat()}
        for t in rows
    ]


@router.get("/estate/stats")
def estate_stats(db: Session = Depends(get_db)):
    endpoints = db.scalars(select(Endpoint)).all()
    return {
        "endpoints": len(endpoints),
        "critical_tier": sum(1 for e in endpoints if e.criticality == "critical"),
        "eol": sum(1 for e in endpoints if e.eol),
    }
