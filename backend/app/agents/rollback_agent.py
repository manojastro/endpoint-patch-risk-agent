"""Rollback Agent: controlled restoration + post-rollback verification."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.engine.rollout_engine import rollback_rings


class RollbackAgent(BaseAgent):
    name = "rollback"

    def run(self, db: Session, investigation, campaign, rings: list[str],
            sequence: int = 8) -> dict:
        result = rollback_rings(db, campaign, rings)
        facts = [
            Fact("rollout.rollback",
                 f"Rolled back rings {rings}: restored {result['restored_count']} "
                 f"device(s) to pre-campaign patch state.", "high"),
            Fact("validations.table",
                 f"Post-rollback validation "
                 f"{'passed' if result['validation_passed'] else 'FAILED'} on all "
                 f"restored devices.", "high"),
        ]
        output = {**result}
        self.record_stage(db, investigation, sequence, facts, output,
                          "Confirm the rollback restored a healthy known-good state.")
        self.record_decision(
            db, investigation,
            decision=f"Rollback of {rings} executed and verified.",
            confidence=0.95 if result["validation_passed"] else 0.5,
            evidence_ids=[], alternatives=["keep failed state (rejected)"],
            risk_level="high", requires_approval=True,
        )
        return output
