"""Shared deterministic domain helpers."""
from __future__ import annotations

import hashlib

# Canonical ring order (execution sequence).
RING_ORDER: list[str] = ["RING_0", "RING_1", "RING_2", "RING_3", "RING_4"]

FAILURE_CLASSES: tuple[str, ...] = (
    "disk_space",
    "app_crash",
    "boot_failure",
    "driver_conflict",
    "av_conflict",
    "network_loss",
    "partial_install",
    "missing_prereq",
)

TRANSIENT_FAILURE_CLASSES = {"network_loss", "partial_install"}

CRITICALITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

SEVERITY_RANK = {"low": 0, "moderate": 1, "high": 2, "critical": 3}


def stable_ratio(key: str) -> float:
    """Deterministic pseudo-random float in [0, 1) derived from a string key.

    Replaces runtime randomness so outcomes are reproducible across runs
    given the same world seed embedded in the key.
    """
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(2 ** 64)


def parse_version(version: str) -> tuple:
    """Parse '7.3.1' style versions into comparable tuples ('7.3.1b' falls back)."""
    parts: list = []
    for chunk in str(version).replace("-", ".").split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
        suffix = chunk[len(digits):]
        if suffix:
            parts.append(suffix)
    return tuple(parts)


def version_lt(a: str, b: str) -> bool:
    return _cmp_versions(parse_version(a), parse_version(b)) < 0


def version_gte(a: str, b: str) -> bool:
    return not version_lt(a, b)


def _cmp_versions(a: tuple, b: tuple) -> int:
    length = max(len(a), len(b))
    pa = list(a) + [0] * (length - len(a))
    pb = list(b) + [0] * (length - len(b))
    for x, y in zip(pa, pb):
        if isinstance(x, str) or isinstance(y, str):
            xs, ys = str(x), str(y)
            if xs != ys:
                return -1 if xs < ys else 1
        elif x != y:
            return -1 if x < y else 1
    return 0


def failure_rate(failures: int, total: int) -> float:
    return (failures / total) if total else 0.0


def evaluate_stop_condition(
    ring: str,
    failure_rate_value: float,
    threshold: float,
    critical_boot_failures: int,
) -> tuple[bool, str]:
    """Autonomous stop policy. Returns (halt?, reason).

    Rules:
      - failure rate above ring threshold -> halt
      - ANY boot failure on a critical-tier device -> halt immediately
    """
    if critical_boot_failures > 0:
        return True, (
            f"{ring}: {critical_boot_failures} boot failure(s) on critical-tier "
            f"device(s); halting regardless of rate."
        )
    if failure_rate_value > threshold:
        return True, (
            f"{ring}: failure rate {failure_rate_value:.2%} exceeds stop "
            f"threshold {threshold:.2%}."
        )
    return False, ""
