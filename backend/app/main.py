"""FastAPI application factory.

CORS from env, safe error responses (no stack traces), static SPA mounted
LAST so API routes take precedence.
"""
from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.db import create_all

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("patch_risk_agent")


def _create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Autonomous endpoint patch risk analysis and safe staged rollout.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    create_all()

    from app.api import (
        routes_campaigns, routes_fleet, routes_meta, routes_ops,
    )
    app.include_router(routes_meta.router)
    app.include_router(routes_fleet.router)
    app.include_router(routes_campaigns.router)
    app.include_router(routes_ops.router)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        request_id = str(uuid.uuid4())[:8]
        logger.error("unhandled error [%s] on %s: %s",
                     request_id, request.url.path, exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "internal error", "request_id": request_id},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"detail": "validation error",
                     "errors": [
                         {"loc": [str(p) for p in e.get("loc", [])],
                          "msg": e.get("msg", ""), "type": e.get("type", "")}
                         for e in exc.errors()
                     ]},
        )

    # Static SPA mounted LAST: /api/v1 + /health etc. win over the file system.
    frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True),
                  name="frontend")
    else:  # pragma: no cover - container/dev parity guard
        logger.warning("frontend directory not found at %s", frontend_dir)

    return app


app = _create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8014)
