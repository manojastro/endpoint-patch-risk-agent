"""Shared pytest fixtures.

Environment is configured BEFORE app imports so settings pick up test values.
A single world database is created per session; modules that need pristine
state reseed via the `reseed` helper (deterministic -> identical world).
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND = PROJECT_ROOT / "backend"
for p in (str(BACKEND),):
    if p not in sys.path:
        sys.path.insert(0, p)

import os  # noqa: E402

os.environ["DATABASE_URL"] = "sqlite:///./data/test_world.db"
os.environ["ESTATE_SIZE"] = "600"
os.environ["SIM_SEED"] = "1337"
os.environ["LLM_MODE"] = "mock"
os.environ["LOG_LEVEL"] = "WARNING"

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def world():
    """Session-wide seeded world + session factory."""
    import app.db as adb
    from simulator import seed_world

    # Fresh file per session keeps runs hermetic.
    db_path = BACKEND / "data" / "test_world.db"
    for suffix in ("", "-wal", "-shm"):
        f = Path(str(db_path) + suffix)
        if f.exists():
            f.unlink()
    adb.reset_engine_for_url(f"sqlite:///{db_path.as_posix()}")
    adb.create_all()
    db = adb.SessionLocal()
    seed_world(db, estate_size=int(os.environ["ESTATE_SIZE"]))
    db.close()
    yield adb
    adb.dispose()


@pytest.fixture()
def dbsession(world):
    """A DB session against the shared world (commits persist by design)."""
    db = world.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def reseed(world):
    """Callable fixture: reseed the shared world on demand."""
    from simulator import seed_world

    def _reseed(estate_size: int = 600):
        db = world.SessionLocal()
        try:
            result = seed_world(db, estate_size=estate_size)
            return result
        finally:
            db.close()

    return _reseed


@pytest.fixture()
def client(world):
    """FastAPI TestClient bound to the shared world."""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def catalog_rows(dbsession):
    from sqlalchemy import select
    from app.models import Patch

    rows = dbsession.scalars(select(Patch)).all()
    yield rows


@pytest.fixture()
def patch_by_id(catalog_rows):
    return {p.patch_id: p for p in catalog_rows}
