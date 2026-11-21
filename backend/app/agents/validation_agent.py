"""Validation Agent: post-ring health verification summary."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.models import Validation


def summarize_validations(validations: list[Validation]) -> dict:
    total = len(validations)
    passed = sum(1 for v in validations if v.passed)
    failed_checks: dict[str, int] = {}
    for v in validations:
        for c in v.checks or []:
            if not c.get("passed"):
                failed_checks[c["check"]] = failed_checks.get(c["check"], 0) + 1
    return {
        "validated_devices": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "failed_check_breakdown": failed_checks,
    }


class ValidationAgent(BaseAgent):
    name = "validation"

    def run(self, db: Session, investigation, campaign_id: int, ring: str,
            sequence: int = 9) -> dict:
        rows = db.scalars(select(Validation).where(
            Validation.campaign_id == campaign_id,
            Validation.phase == "post_patch")).all()
        summary = summarize_validations(rows)
        facts = [
            Fact("validations.table",
                 f"{summary['validated_devices']} device validation(s): "
                 f"{summary['passed']} passed / {summary['failed']} failed.", "high"),
        ]
        if summary["failed_check_breakdown"]:
            facts.append(Fact(
                "validations.table",
                f"Failing checks: {summary['failed_check_breakdown']}.", "high"))
        output = {"ring": ring, **summary}
        self.record_stage(db, investigation, sequence, facts, output,
                          "Verify post-patch device health for the ring.")
        return output
