"""Failure RCA Agent: taxonomy classification + root-cause correlation."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.engine.rca import build_rca_records, classify_failures
from app.models import Action, DeviceInstallResult, Endpoint


def collect_ring_failures(db: Session, campaign_id: int, ring: str | None = None):
    query = select(DeviceInstallResult).where(
        DeviceInstallResult.campaign_id == campaign_id,
        DeviceInstallResult.outcome == "failed",
    )
    if ring:
        query = query.where(DeviceInstallResult.ring == ring)
    return db.scalars(query).all()


class RcaAgent(BaseAgent):
    name = "rca"

    def run(self, db: Session, investigation, campaign, ring: str,
            patch_row, sequence: int = 7) -> dict:
        failures = collect_ring_failures(db, campaign.id, ring)
        failed_pairs = []
        for row in failures:
            ep = db.get(Endpoint, row.endpoint_id)
            if ep is not None:
                failed_pairs.append((ep, row.failure_class or "unknown"))
        # Succeeded peers in the SAME ring for differential analysis.
        succeeded_rows = db.scalars(select(DeviceInstallResult).where(
            DeviceInstallResult.campaign_id == campaign.id,
            DeviceInstallResult.ring == ring,
            DeviceInstallResult.outcome.in_(("success", "pending_reboot")),
        )).all()
        succeeded_eps = [db.get(Endpoint, r.endpoint_id) for r in succeeded_rows]
        succeeded_eps = [e for e in succeeded_eps if e is not None]

        counts = classify_failures(
            [{"failure_class": r.failure_class, "error_detail": r.error_detail}
             for r in failures]
        )
        records, hypotheses = build_rca_records(
            None, campaign.id, ring, failed_pairs, succeeded_eps, patch_row
        )
        for rec in records:
            db.add(rec)
        top = hypotheses[0] if hypotheses else None

        actions = []
        if top:
            actions.append(Action(
                campaign_id=campaign.id,
                action_type="exclude_cohort_recommended",
                target={"app_name": top["app_name"],
                        "version_below": top["catalog_version_below"]},
                status="recommended", reason=top["recommended_action"],
            ))
        actions.append(Action(
            campaign_id=campaign.id, action_type="rollback_recommended",
            target={"rings": [ring]}, status="recommended",
            reason=f"halted at {ring}: {sum(counts.values())} failure(s)",
        ))

        facts = [
            Fact("install.results",
                 f"Ring {ring} recorded {len(failures)} failed install(s); "
                 f"classification {counts}.", "high"),
        ]
        for h in hypotheses[:3]:
            facts.append(Fact(
                "rca.correlation",
                f"{h['root_cause']} (confidence {h['confidence']:.2f}; "
                f"catalog match={h['matches_catalog_known_issue']}).",
                "high" if h["matches_catalog_known_issue"] else "medium",
            ))
        output = {
            "failure_classes": counts,
            "hypotheses": hypotheses,
            "records_persisted": len(records),
        }
        self.record_stage(db, investigation, sequence, facts, output,
                          "Classify the observed failures and correlate root cause.")
        if top:
            self.record_decision(
                db, investigation,
                decision=(f"Halt confirmed. Root cause: {top['root_cause']} "
                          f"Recommended: {top['recommended_action']}"),
                confidence=top["confidence"], evidence_ids=[],
                alternatives=["continue despite failures (rejected: blast radius unknown)",
                              "fleet-wide rollback without RCA (rejected: loses cohort signal)"],
                risk_level="high", requires_approval=False,
            )
        return output
