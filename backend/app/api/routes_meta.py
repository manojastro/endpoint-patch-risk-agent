"""Meta / health / metrics routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Endpoint, Patch
from app.schemas import HealthInfo, MetaInfo, ReadinessInfo

router = APIRouter()


@router.get("/health", response_model=HealthInfo)
def health(db: Session = Depends(get_db)):
    settings = get_settings()
    db_ok = True
    try:
        db.execute(select(1))
    except Exception:  # pragma: no cover
        db_ok = False
    return HealthInfo(status="ok" if db_ok else "degraded", database=settings.DATABASE_URL)


@router.get("/readiness", response_model=ReadinessInfo)
def readiness(db: Session = Depends(get_db)):
    endpoints = db.scalar(select(func.count()).select_from(Endpoint)) or 0
    patches = db.scalar(select(func.count()).select_from(Patch)) or 0
    ready = endpoints > 0 and patches > 0
    return ReadinessInfo(
        ready=ready, endpoints_seeded=endpoints, patches_seeded=patches,
        detail="world seeded" if ready else "run POST /api/v1/simulator/seed",
    )


@router.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@router.get("/api/v1/meta", response_model=MetaInfo)
def meta():
    settings = get_settings()
    return MetaInfo(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        llm_mode=settings.LLM_MODE,
        mock_mode=settings.LLM_MODE.lower() == "mock",
        estate_size=settings.ESTATE_SIZE,
        sim_seed=settings.SIM_SEED,
        database=settings.DATABASE_URL.split("///")[-1],
    )
