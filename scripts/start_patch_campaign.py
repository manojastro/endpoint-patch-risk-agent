"""Demo: the DESIGNED bad-patch scenario, end to end.

KB-SIM-2026-002 (critical Windows 10 cumulative with exploited CVEs) is
publicly known in the catalog to crash warehouse-scanner-suite < 7.4.2, and
~8% of the warehouse department still runs 7.3.1. Under the default
"canary_prove" policy the planner deliberately seats two scanner-cohort
representatives in the RING_1 canary. The canary fails, the autonomous stop
condition halts the campaign before any broad ring, RCA names the root cause,
and a controlled rollback restores every touched device.

Run from the project root:
    .venv\\Scripts\\python.exe scripts\\start_patch_campaign.py [--reseed]
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND))
# The default DATABASE_URL is relative (sqlite:///./data/patch_risk.db);
# pin the working directory so the world lands in backend/data regardless
# of where the script is invoked from.
os.chdir(BACKEND)

os.environ.setdefault("LLM_MODE", "mock")
os.environ.setdefault("LOG_LEVEL", "WARNING")

from simulator.generate_catalog import BAD_PATCH_ID  # noqa: E402


def line(char="-", width=78):
    print(char * width)


def print_ring(result: dict) -> None:
    line()
    print(f"RING {result['ring']}  status={result['status']}")
    print(f"  devices={result['device_count']} success={result['success_count']} "
          f"pending_reboot={result['pending_reboot_count']} "
          f"failed={result['failure_count']}")
    print(f"  failure_rate={result['failure_rate']:.1%} "
          f"(stop threshold {result['threshold']:.0%})")
    if result["failure_classes"]:
        print(f"  failure classes: {result['failure_classes']}")
    if result["stop_triggered"]:
        print(f"  *** AUTONOMOUS STOP *** {result['stop_reason']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reseed", action="store_true",
                        help="reseed the simulated world first")
    parser.add_argument("--estate", type=int, default=None,
                        help="estate size when reseeding (default ESTATE_SIZE)")
    args = parser.parse_args()

    import app.db as adb
    from sqlalchemy import select

    from app.models import Endpoint
    from app.workflow import engine as wf
    from simulator import seed_world, world_is_seeded

    adb.create_all()
    db = adb.SessionLocal()
    try:
        if args.reseed or not world_is_seeded(db):
            started = time.perf_counter()
            counts = seed_world(db, estate_size=args.estate)
            print(f"Seeded world: {counts['endpoints']} endpoints, "
                  f"{counts['patches']} patches, {counts['findings']} findings "
                  f"in {time.perf_counter() - started:.1f}s")
        else:
            n = db.scalar(select(Endpoint.id).limit(1))
            print(f"Using existing seeded world (endpoint row present: {n is not None})")

        line("=")
        print(f"CAMPAIGN: rollout of {BAD_PATCH_ID} (policy=canary_prove)")
        line("=")

        campaign = wf.create_campaign(db, BAD_PATCH_ID, "demo-bad-patch",
                                      at_risk_policy="canary_prove")
        investigation = wf.run_investigation(db, campaign)
        inv = investigation
        print(f"Investigation: fleet={inv['inventory']['total_endpoints']} "
              f"eligible={inv['compatibility']['eligible_total']} "
              f"KEV CVEs={inv['vulnerabilities']['kev_cves']} "
              f"P1 share={inv['risk_distribution'].get('P1', 0)}")

        plan_output = wf.plan_campaign(db, campaign)
        for p in plan_output["plans"]:
            print(f"  plan {p['ring']}: {p['size']} devices, "
                  f"threshold {p['threshold']:.0%}")
        for ring_note in [p for p in plan_output["plans"] if p["ring"] == "RING_1"]:
            print(f"  note: {ring_note['criteria_note']}")

        approval = wf.request_start(db, campaign,
                                    reason="demo: exploited CVE, staged rollout")
        # Gate proof: advancing before approval must be refused.
        try:
            wf.advance(db, campaign)
            print("UNEXPECTED: advance succeeded without approval")
            return 1
        except PermissionError as exc:
            print(f"Gate check OK (advance refused pre-approval): {exc}")

        wf.approve(db, approval, decided_by="demo-operator",
                   note="approved for staged rollout")

        halted = False
        guard = 0
        while campaign.status not in ("COMPLETED", "FAILED") and guard < 8:
            guard += 1
            result = wf.advance(db, campaign)
            ring_result = result["ring_execution"]
            print_ring(ring_result)
            if ring_result["stop_triggered"]:
                halted = True
                rca = result.get("rca") or {}
                print(f"RCA ({rca.get('records_persisted', 0)} records persisted):")
                for h in rca.get("hypotheses", [])[:3]:
                    print(f"  hypothesis: {h.get('root_cause', h.get('app_name'))}")
                    if h.get("app_name"):
                        print(f"    app={h['app_name']} "
                              f"failing version={h.get('dominant_failing_version', '?')} "
                              f"floor={h.get('catalog_version_below') or '?'} "
                              f"catalog-confirmed={h.get('matches_catalog_known_issue')} "
                              f"confidence={h.get('confidence', 0):.2f}")
                    print(f"    recommendation: {h.get('recommended_action', '')}")
                break
        assert halted, "designed bad patch must halt autonomously"

        print(f"Campaign status after halt: {campaign.status} ({campaign.stop_reason})")
        rb = wf.run_rollback(db, campaign)
        print(f"Rollback: restored={rb['restored_count']} devices, "
              f"post-rollback validation passed={rb['validation_passed']}")
        print(f"Final campaign status: {campaign.status}")
        line("=")
        print("DEMO COMPLETE: bad patch caught in canary, halted before broad "
              "rings, root-caused and rolled back cleanly.")
        db.commit()  # persist the campaign story for the SPA/API
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
