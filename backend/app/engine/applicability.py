"""Patch applicability, known-issue matching, and prerequisite/disk checks."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.common import version_lt


@dataclass
class ApplicabilityResult:
    applicable: bool
    reason_code: str  # os_mismatch | already_installed | up_to_date | superseded | eligible
    detail: str = ""


COMPLIANT_STATES = {"installed", "up_to_date"}


def is_applicable(endpoint, patch_row, patch_states: dict[str, str]) -> ApplicabilityResult:
    """Decide whether `patch_row` is installable on `endpoint`.

    `patch_states` maps patch_id -> state for this endpoint.
    """
    if getattr(patch_row, "target_os", None) != getattr(endpoint, "os", None):
        return ApplicabilityResult(False, "os_mismatch", "patch targets a different OS")
    current = patch_states.get(patch_row.patch_id)
    if current in COMPLIANT_STATES:
        return ApplicabilityResult(
            False,
            "already_installed" if current == "installed" else "up_to_date",
            f"state={current}",
        )
    superseded_by = getattr(patch_row, "superseded_by", None)
    if superseded_by and patch_states.get(superseded_by) in COMPLIANT_STATES:
        return ApplicabilityResult(
            False, "superseded", f"superseded by {superseded_by} (installed/up-to-date)"
        )
    return ApplicabilityResult(True, "eligible")


def missing_prerequisites(patch_row, patch_states: dict[str, str]) -> list[str]:
    prereqs = list(getattr(patch_row, "prerequisites", None) or [])
    return [
        p for p in prereqs
        if patch_states.get(p) not in COMPLIANT_STATES
    ]


def disk_sufficient(endpoint, patch_row) -> bool:
    required_gb = (getattr(patch_row, "disk_space_required_mb", 0) or 0) / 1024.0
    free = float(getattr(endpoint, "disk_free_gb", 0) or 0)
    return free >= required_gb


def get_software_version(endpoint, app_name: str) -> str | None:
    for item in getattr(endpoint, "software", None) or []:
        if item.get("name") == app_name:
            return item.get("version")
    return None


@dataclass
class IssueMatch:
    issue: object            # PatchKnownIssue-like row
    installed_version: str
    failure_class: str


def matching_known_issues(endpoint, patch_row) -> list[IssueMatch]:
    """Publicly documented incompatibilities that hit this specific endpoint."""
    matches: list[IssueMatch] = []
    for issue in getattr(patch_row, "known_issues", None) or []:
        installed = get_software_version(endpoint, issue.app_name)
        if installed is not None and version_lt(installed, issue.version_below):
            matches.append(IssueMatch(issue, installed, issue.failure_class))
    return matches


def at_risk_count(endpoints, patch_row) -> int:
    return sum(1 for e in endpoints if matching_known_issues(e, patch_row))


def cohort_signature(endpoint, match: IssueMatch) -> str:
    return f"{endpoint.department}|{endpoint.os}|{match.issue.app_name}|{match.issue.version_below}"


def build_cohorts(endpoints, patch_row) -> dict[str, dict]:
    """Group at-risk endpoints into cohorts keyed by signature."""
    cohorts: dict[str, dict] = {}
    for e in endpoints:
        for m in matching_known_issues(e, patch_row):
            sig = cohort_signature(e, m)
            entry = cohorts.setdefault(sig, {
                "signature": sig,
                "department": e.department,
                "os": e.os,
                "app_name": m.issue.app_name,
                "version_below": m.issue.version_below,
                "failure_class": m.failure_class,
                "description": m.issue.description,
                "endpoint_ids": [],
                "sample_versions": [],
            })
            entry["endpoint_ids"].append(e.id)
            if len(entry["sample_versions"]) < 5:
                entry["sample_versions"].append(m.installed_version)
    return cohorts
