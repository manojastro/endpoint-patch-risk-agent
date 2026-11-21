"""Rollout Planning Agent: ring assignments via the rollout engine."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.engine.rollout_engine import plan_rings


class PlanningAgent(BaseAgent):
    name = "planning"

    def run(self, db: Session, investigation, campaign, patch_row, endpoints,
            states_by_ep: dict, sequence: int = 6) -> dict:
        plans = plan_rings(db, campaign, patch_row, endpoints, states_by_ep)
        plan_view = [
            {"ring": p.ring, "position": p.position, "size": p.size,
             "threshold": p.threshold, "criteria_note": p.criteria_note}
            for p in sorted(plans, key=lambda p: p.position)
        ]
        facts = [
            Fact("rollout.planner",
                 f"{campaign.eligible_count} eligible endpoints assigned to "
                 f"{len(plan_view)} rings.", "high"),
        ]
        for pv in plan_view:
            facts.append(Fact(
                "rollout.planner",
                f"{pv['ring']}: {pv['size']} device(s), stop threshold "
                f"{pv['threshold']:.0%}. {pv['criteria_note']}",
                "high", f"ring_plan:{campaign.id}:{pv['ring']}",
            ))
        output = {"plans": plan_view,
                  "exclusion_reasons": dict(campaign.exclusion_reasons or {})}
        self.record_stage(db, investigation, sequence, facts, output,
                          "Justify the staged rollout ring plan.")
        self.record_decision(
            db, investigation,
            decision="Proceed with staged rollout; require human approval before "
                     "any device is touched.",
            confidence=0.9, evidence_ids=[],
            alternatives=["big-bang deployment (rejected: no early failure signal)",
                          "indefinite deferral (rejected: exploited CVE exposure)"],
            risk_level="high", requires_approval=True,
        )
        return output
