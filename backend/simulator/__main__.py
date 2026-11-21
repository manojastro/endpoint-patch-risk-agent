"""CLI seed entry: python -m simulator [--estate-size N] [--seed N]"""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the patch-risk simulated world")
    parser.add_argument("--estate-size", type=int, default=None)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    import app.db as adb
    from . import seed_world, world_is_seeded
    from sqlalchemy import select, func
    from app.models import Endpoint

    adb.create_all()
    db = adb.SessionLocal()
    try:
        result = seed_world(db, estate_size=args.estate_size, seed=args.seed)
        count = db.scalar(select(func.count()).select_from(Endpoint))
        seeded = world_is_seeded(db)
        print(
            f"Seeded world: endpoints={result['endpoints']} patches={result['patches']} "
            f"patch_states={result['patch_states']} findings={result['findings']} "
            f"departments={result['departments']} in {result['duration_ms']} ms "
            f"(verified={seeded}, endpoint_rows={count})"
        )
        return 0 if seeded and count == result["endpoints"] else 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
