"""Patch Compatibility Agent: patch-vs-fleet matrix and at-risk cohorts."""
from __future__ import annotations

from collections import defaultdict


from app.agents.base import BaseAgent, Fact
from app.engine.applicability import build_cohorts


def matrix_cells_detailed(patch_row, endpoints, states_by_ep, policy: str) -> list[dict]:
    """Fill the matrix with per-cell applicable / incompatible / at-risk counts."""
    from app.engine.applicability import (
        disk_sufficient, is_applicable, matching_known_issues, missing_prerequisites,
    )
    cells: dict[tuple[str, str], dict] = {}

    def cell_for(e):
        key = (e.department, e.os)
        return cells.setdefault(key, {
            "department": e.department, "os": e.os, "total": 0, "applicable": 0,
            "incompatible": 0, "at_risk": 0, "blocked_disk": 0, "missing_prereq": 0,
        })

    for e in endpoints:
        c = cell_for(e)
        c["total"] += 1
        states = states_by_ep.get(e.id, {})
        res = is_applicable(e, patch_row, states)
        if not res.applicable:
            if res.reason_code == "already_installed":
                c["incompatible"] += 0  # not incompatible; simply not applicable
            continue
        if missing_prerequisites(patch_row, states):
            c["missing_prereq"] += 1
            continue
        if not disk_sufficient(e, patch_row):
            c["blocked_disk"] += 1
            continue
        if matching_known_issues(e, patch_row):
            c["at_risk" if policy == "canary_prove" else "incompatible"] += 1
            continue
        c["applicable"] += 1
    return sorted(cells.values(), key=lambda c: (-c["total"], c["department"], c["os"]))


class CompatibilityAgent(BaseAgent):
    name = "compatibility"

    def run(self, db: Session, investigation, patch_row, endpoints,
            states_by_ep, policy: str, sequence: int = 3) -> dict:
        cohorts = build_cohorts(endpoints, patch_row)
        cells = matrix_cells_detailed(patch_row, endpoints, states_by_ep, policy)
        eligible_total = sum(c["applicable"] + c["at_risk"] for c in cells)
        facts = [
            Fact("compatibility.matrix",
                 f"{eligible_total} of {len(endpoints)} endpoints are installable "
                 f"for {patch_row.patch_id} under policy '{policy}'.", "high"),
            Fact("compatibility.matrix",
                 f"{len(cohorts)} at-risk cohort(s) detected.", "high"),
        ]
        for sig, cohort in sorted(cohorts.items()):
            facts.append(Fact(
                "catalog.known_issues",
                f"Cohort {sig}: {len(cohort['endpoint_ids'])} endpoint(s) run "
                f"{cohort['app_name']} below {cohort['version_below']} "
                f"(expected failure class: {cohort['failure_class']}).",
                "high", f"patch_known_issue:{patch_row.patch_id}",
            ))
        output = {
            "patch_id": patch_row.patch_id,
            "policy": policy,
            "eligible_total": eligible_total,
            "cohorts": [v for _k, v in sorted(cohorts.items())],
            "cells": cells,
        }
        self.record_stage(db, investigation, sequence, facts, output,
                          "Summarize patch-fleet compatibility and exposure cohorts.")
        self.record_decision(
            db, investigation,
            decision=(
                f"Treat {sum(len(c['endpoint_ids']) for c in cohorts.values())} "
                f"at-risk endpoint(s) via policy '{policy}'"
                if cohorts else "No known incompatibilities apply; proceed normally."
            ),
            confidence=0.9 if cohorts else 0.8,
            evidence_ids=[], alternatives=["exclude", "canary_prove"],
            risk_level="medium" if cohorts else "low",
            requires_approval=False,
        )
        return output
