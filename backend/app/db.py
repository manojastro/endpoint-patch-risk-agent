"""Database engine/session setup (SQLAlchemy 2.x)."""
import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _database_url() -> str:
    return get_settings().DATABASE_URL


def make_engine(database_url: str | None = None):
    url = database_url or _database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        # Ensure the sqlite parent directory exists.
        path_part = url.split("///", 1)[-1]
        if path_part and path_part != ":memory:":
            Path(path_part).parent.mkdir(parents=True, exist_ok=True)
        connect_args["check_same_thread"] = False
    engine = create_engine(url, connect_args=connect_args, future=True)

    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _record):  # pragma: no cover - glue
            cur = dbapi_conn.cursor()
            # Simulator-grade durability tradeoff: WAL + no per-commit fsync.
            # Documented in LIMITATIONS.md; swap DATABASE_URL to PostgreSQL
            # (psycopg driver is installed) for production-grade durability.
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=OFF")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


engine = None
SessionLocal = None


def init_engine() -> None:
    global engine, SessionLocal
    if engine is None:
        engine = make_engine()
        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    """FastAPI dependency yielding a session."""
    init_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    init_engine()
    from app import models  # noqa: F401  (register mappings)

    Base.metadata.create_all(engine)


def reset_engine_for_url(database_url: str) -> None:
    """Point the module at a specific URL (used by tests / evaluator sandboxes)."""
    global engine, SessionLocal
    engine = make_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def dispose() -> None:
    global engine, SessionLocal
    if engine is not None:
        engine.dispose()
    engine = None
    SessionLocal = None
