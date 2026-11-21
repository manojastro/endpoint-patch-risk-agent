"""Demo: the clean reference patch rolls out through all five rings.

KB-SIM-2026-006 (Ubuntu 22.04 kernel security update, no known issues) walks
RING_0 lab -> RING_1 canary -> RING_2 pilot -> RING_3 department wave ->
RING_4 broad with every ring under its stop threshold, and the campaign
finishes COMPLETED.

Run from the project root:
    .venv\\Scripts\\python.exe scripts\\run_clean_campaign_demo.py [--reseed]
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
# Pin the working directory so the relative default DATABASE_URL resolves to
# backend/data/patch_risk.db regardless of where the script is invoked from.
os.chdir(BACKEND)

os.environ.setdefault("LLM_MODE", "mock")
os.environ.setdefault("LOG_LEVEL", "WARNING")

from simulator.generate_catalog import CLEAN_PATCH_ID  # noqa: E402


def line(char="-", width=78):
    print(char * width)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reseed", action="store_true")
    parser.add_argument("--estate", type=int, default=None)
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
            print(f"Seeded world: {counts['endpoints']} endpoints in "
                  f"{time.perf_counter() - started:.1f}s")

        line("=")
        print(f"CAMPAIGN: rollout of {CLEAN_PATCH_ID} (clean reference patch)")
        line("=")

        campaign = wf.create_campaign(db, CLEAN_PATCH_ID, "demo-clean-patch")
        wf.run_investigation(db, campaign)
        plan_output = wf.plan_campaign(db, campaign)
        for p in plan_output["plans"]:
            print(f"  plan {p['ring']}: {p['size']} devices, "
                  f"threshold {p['threshold']:.0%}")

        approval = wf.request_start(db, campaign,
                                    reason="demo: clean patch staged rollout")
        wf.approve(db, approval, decided_by="demo-operator")

        guard = 0
        completed = False
        while campaign.status not in ("COMPLETED", "FAILED") and guard < 10:
            guard += 1
            result = wf.advance(db, campaign)
            r = result["ring_execution"]
            print(f"RING {r['ring']}: {r['status']} devices={r['device_count']} "
                  f"failed={r['failure_count']} rate={r['failure_rate']:.1%} "
                  f"(threshold {r['threshold']:.0%})")
            if result.get("completed"):
                completed = True

        print(f"Final status: {campaign.status}")
        line("=")
        if campaign.status == "COMPLETED":
            print("DEMO COMPLETE: clean patch rolled out through all five "
                  "rings without breaching any stop threshold.")
            db.commit()  # persist the campaign for the SPA/API
            return 0
        print("UNEXPECTED: clean patch did not complete.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
