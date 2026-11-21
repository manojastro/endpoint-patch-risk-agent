"""Agent tool infrastructure: specs, registry, allow-list, input validation,
and an append-only audit log. No shell/subprocess tools exist here by design."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.metrics import TOOL_CALLS_TOTAL, TOOL_DURATION, TOOL_ERRORS_TOTAL
from app.models import ToolCall


class ToolError(Exception):
    """Raised when a tool refuses or fails; message is safe to surface."""


class ToolPermissionError(ToolError):
    """Raised when a gated tool is invoked without satisfying its gate."""


@dataclass
class ToolSpec:
    name: str
    purpose: str
    input_schema: dict[str, Any]
    permission: str            # "agent" | "human-approval"
    risk_level: str            # read | write | high
    timeout_s: float
    handler: Callable          # handler(db, arguments) -> dict


_TYPES = {"string": str, "integer": int, "number": (int, float),
          "boolean": bool, "array": list, "object": dict}


def validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
    """Minimal JSON-schema style validation (required / type / enum)."""
    properties = schema.get("properties", {})
    for req in schema.get("required", []):
        if req not in arguments:
            raise ToolError(f"missing required argument '{req}'")
    for key, value in arguments.items():
        if properties and key not in properties:
            # allow extra simple keys only when additionalProperties unset
            if schema.get("additionalProperties") is False:
                raise ToolError(f"unexpected argument '{key}'")
            continue
        spec = properties.get(key, {})
        expected = spec.get("type")
        if expected and not isinstance(value, _TYPES[expected]):
            raise ToolError(
                f"argument '{key}' must be {expected}, got {type(value).__name__}"
            )
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"argument '{key}' must be one of {spec['enum']}")
        if expected == "integer" and isinstance(value, bool):
            raise ToolError(f"argument '{key}' must be integer")


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"duplicate tool {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools.keys())

    def list_specs(self) -> list[dict]:
        return [
            {
                "name": t.name, "purpose": t.purpose,
                "input_schema": t.input_schema, "permission": t.permission,
                "risk_level": t.risk_level, "timeout_s": t.timeout_s,
            }
            for t in (self._tools[n] for n in sorted(self._tools))
        ]

    def execute(self, db: Session, name: str, arguments: dict[str, Any],
                caller: str = "agent") -> dict:
        started = time.perf_counter()
        spec = self._tools.get(name)
        ok = True
        error = ""
        summary = ""
        try:
            if spec is None:
                raise ToolError(f"unknown tool '{name}'")
            if not isinstance(arguments, dict):
                raise ToolError("arguments must be an object")
            validate_arguments(spec.input_schema, arguments)
            result = spec.handler(db, arguments)
            summary = json.dumps(result, default=str)[:400]
            return result
        except ToolError as exc:
            ok = False
            error = str(exc)
            TOOL_ERRORS_TOTAL.labels(name).inc()
            raise
        except Exception as exc:  # unexpected -> audited, generic surface
            ok = False
            error = f"{type(exc).__name__}: {exc}"
            TOOL_ERRORS_TOTAL.labels(name).inc()
            raise ToolError(error) from exc
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            TOOL_CALLS_TOTAL.labels(name, "ok" if ok else "error").inc()
            TOOL_DURATION.labels(name).observe((time.perf_counter() - started))
            try:
                db.add(ToolCall(
                    tool_name=name, arguments=arguments if ok else {
                        "_redacted_arguments": _redact(arguments or {})},
                    ok=ok, error=error, caller=caller,
                    risk_level=spec.risk_level if spec else "unknown",
                    duration_ms=duration_ms, result_summary=summary if ok else "",
                ))
                db.commit()
            except Exception:  # audit must never break execution paths
                db.rollback()


_SENSITIVE_KEYS = {"api_key", "authorization", "password", "secret", "token"}


def _redact(arguments: dict) -> dict:
    out = {}
    for k, v in arguments.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


REGISTRY = ToolRegistry()


def register_all() -> ToolRegistry:
    """Idempotently populate the global registry."""
    if REGISTRY.names():
        return REGISTRY
    from . import fleet_tools as ft

    for spec in ft.build_tools():
        REGISTRY.register(spec)
    return REGISTRY
