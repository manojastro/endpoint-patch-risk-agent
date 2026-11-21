"""Risk Agent: persists deterministic risk assessments for a campaign."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.engine.dependencies import dependents_count, build_dependency_graph
from app.engine.risk_engine import assess_endpoint_patch
from app.models import RiskAssessment


def assess_fleet(db: Session, campaign_id: int | None, patch_row,
                 eligible_endpoints: list) -> tuple[list[dict], dict[str, int]]:
    """Compute + persist assessments for the eligible set."""
    graph = build_dependency_graph(eligible_endpoints)
    distribution: defaultdict[str, int] = defaultdict(int)
    assessments: list[dict] = []
    rows = []
    for e in eligible_endpoints:
        result = assess_endpoint_patch(e, patch_row, dependents_count(graph, e.id))
        result["campaign_id"] = campaign_id
        distribution[result["bucket"]] += 1
        assessments.append(result)
        rows.append(RiskAssessment(**result))
    db.add_all(rows)
    db.flush()
    return assessments, dict(distribution)


class RiskAgent(BaseAgent):
    name = "risk"

    def run(self, db: Session, investigation, campaign_id, patch_row,
            eligible_endpoints: list, sequence: int = 5) -> dict:
        assessments, distribution = assess_fleet(db, campaign_id, patch_row,
                                                 eligible_endpoints)
        total = len(assessments) or 1
        p1_share = distribution.get("P1", 0) / total
        top_p1 = sorted(
            (a for a in assessments if a["bucket"] == "P1"),
            key=lambda a: -a["score"],
        )[:5]
        facts = [
            Fact("risk.engine",
                 f"Scored {len(assessments)} endpoint-patch pairs; bucket "
                 f"distribution {dict(sorted(distribution.items()))}.", "high"),
            Fact("risk.engine",
                 f"P1 share is {p1_share:.0%} under persisted audit weights.", "high"),
        ]
        if top_p1:
            facts.append(Fact(
                "risk.engine",
                f"Top P1 scores: {[round(a['score'], 1) for a in top_p1]}.",
                "high"))
        output = {
            "assessed": len(assessments),
            "distribution": dict(sorted(distribution.items())),
            "p1_share": round(p1_share, 4),
            "top_p1_endpoint_ids": [a["endpoint_id"] for a in top_p1],
            "weights": assessments[0]["weights"] if assessments else {},
        }
        self.record_stage(db, investigation, sequence, facts, output,
                          "Summarize the prioritized patch risk landscape.")
        return output
