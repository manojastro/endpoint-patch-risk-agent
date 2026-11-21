"""Deterministic weighted patch risk engine.

Every factor is normalised to 0..100; the weighted sum yields a 0..100 score
mapped to priority buckets P1 (>=70), P2 (>=55), P3 (>=40), P4 (<40).
Weights are constants here and are persisted with every assessment row for
auditability.
"""
from __future__ import annotations

from app.engine.applicability import matching_known_issues
from app.engine.common import CRITICALITY_RANK, SEVERITY_RANK

WEIGHTS: dict[str, float] = {
    "business_criticality": 0.25,
    "patch_severity": 0.20,
    "exploit_availability": 0.15,
    "device_role": 0.08,
    "dependency_impact": 0.08,
    "historical_failures": 0.06,
    "device_health": 0.06,
    "disk_headroom": 0.04,
    "reboot_burden": 0.04,
    "compat_hit": 0.04,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

CRITICALITY_SCORE = {"critical": 95.0, "high": 75.0, "medium": 45.0, "low": 15.0}
SEVERITY_SCORE = {"critical": 100.0, "high": 78.0, "moderate": 45.0, "low": 15.0}

ROLE_SCORES: dict[str, float] = {
    "store-server": 90, "warehouse-server": 88, "finance-app-server": 90,
    "infra-server": 89, "lab-server": 55, "pos-terminal": 88, "build-agent": 82,
    "scanner-handheld": 45, "dock-kiosk": 35, "agent-ws": 50, "supervisor-ws": 52,
    "back-office": 50, "dev-ws": 52, "analyst-ws": 55, "exec-laptop": 58,
    "exec-desktop": 56, "lab-box": 42,
}

BUCKETS: tuple[tuple[float, str], ...] = (
    (70.0, "P1"), (55.0, "P2"), (40.0, "P3"), (float("-inf"), "P4"),
)


def bucket_for_score(score: float) -> str:
    for floor, bucket in BUCKETS:
        if score >= floor:
            return bucket
    return "P4"


def _attr(obj, name, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def compute_factor_values(
    endpoint,
    patch_row,
    dependents_count: int = 0,
) -> dict[str, float]:
    """Normalised 0..100 factor values for one endpoint x patch pair."""
    criticality = _attr(endpoint, "criticality", "medium")
    severity = _attr(patch_row, "severity", "moderate")

    cves = _attr(patch_row, "cves", None) or []
    kev = any(bool(getattr(c, "known_exploited", False)) for c in cves)
    max_cvss = max([float(getattr(c, "cvss", 0.0)) for c in cves] or [0.0])
    exploit = 100.0 if kev else min(100.0, max_cvss * 10.0)

    role = _attr(endpoint, "role", "back-office")
    role_score = float(ROLE_SCORES.get(role, 50))

    dep_impact = float(min(100.0, dependents_count * 25.0))

    hist = int(_attr(endpoint, "historical_patch_failures", 0) or 0)
    hist_score = float(min(100.0, hist * 20.0))

    health = int(_attr(endpoint, "health_score", 60) or 0)
    health_score = float(max(0.0, 100 - health))

    required_gb = (_attr(patch_row, "disk_space_required_mb", 0) or 0) / 1024.0
    free_gb = float(_attr(endpoint, "disk_free_gb", 0) or 0)
    if required_gb <= 0:
        disk_score = 0.0
    else:
        ratio = required_gb / free_gb if free_gb > 0 else float("inf")
        disk_score = 100.0 if ratio >= 0.67 else max(0.0, (ratio - 0.33) / 0.34 * 100.0)

    pending_days = int(_attr(endpoint, "pending_reboot_days", 0) or 0)
    reboot_burden = min(100.0, pending_days * 2.0 + (25.0 if _attr(patch_row, "reboot_required", False) else 0.0))

    compat_hits = matching_known_issues(endpoint, patch_row)
    compat = 100.0 if compat_hits else 0.0

    return {
        "business_criticality": CRITICALITY_SCORE.get(criticality, 45.0),
        "patch_severity": SEVERITY_SCORE.get(severity, 45.0),
        "exploit_availability": exploit,
        "device_role": role_score,
        "dependency_impact": dep_impact,
        "historical_failures": hist_score,
        "device_health": health_score,
        "disk_headroom": disk_score,
        "reboot_burden": reboot_burden,
        "compat_hit": compat,
    }


def compute_score(factor_values: dict[str, float], weights: dict[str, float] | None = None) -> float:
    w = weights or WEIGHTS
    return round(sum(factor_values.get(k, 0.0) * w[k] for k in w), 4)


def assess_endpoint_patch(
    endpoint,
    patch_row,
    dependents_count: int = 0,
) -> dict:
    factors = compute_factor_values(endpoint, patch_row, dependents_count)
    score = compute_score(factors)
    bucket = bucket_for_score(score)
    drivers = sorted(
        ((k, v) for k, v in factors.items() if v > 0),
        key=lambda kv: -(kv[1] * WEIGHTS[kv[0]]),
    )
    top = ", ".join(f"{k}={v:.0f}" for k, v in drivers[:4])
    rationale = (
        f"score {score:.1f} -> {bucket}; dominant factors: {top}."
    )
    return {
        "endpoint_id": _attr(endpoint, "id"),
        "patch_id": getattr(patch_row, "patch_id", None),
        "score": score,
        "bucket": bucket,
        "factor_values": {k: round(v, 2) for k, v in factors.items()},
        "weights": dict(WEIGHTS),
        "rationale": rationale,
    }
