# Interview guide - talking about this project

## The 30-second version

"I built a working patch-rollout decision engine: it scores every endpoint x patch
pair with a weighted risk model, plans a five-ring rollout (lab, canary, pilot,
department, broad), and executes it against a deterministic 2,500-endpoint
simulation. When the canary breach rate crosses 5% it halts autonomously,
runs version-aware root-cause analysis against the patch catalog, and rolls back
with per-device validation. The designed demo is a scanner-suite incompatibility
affecting ~8% of one department: it gets caught at RING_1 at a 50% failure rate
and never reaches the broad fleet."

## Questions you should expect

**Why rings? Why these sizes?**
Blast-radius control. Ring sizes are policy (1% / 5% / 30%), thresholds are
per-ring policy too - stricter for early rings where signal is noisy. Both are
config, not code. The interesting bit is RING_1 composition: under `canary_prove`
the planner deliberately seats two representatives of each known at-risk cohort
in the canary, so detection of a KNOWN-suspect issue is deterministic rather than
a probability gamble.

**How does the halt actually work?**
After each ring installs, failure rate = failed / attempted and compared strictly
greater-than the ring threshold; any boot failure on a critical-tier device halts
immediately regardless of rate. Halting triggers RCA + validation agents inside
the same workflow step, so by the time a human looks there's already a root cause
and a rollback recommendation.

**Where does risk scoring come from?**
Ten weighted factors summing to 1.0 - business criticality 0.25, patch severity
0.20, exploit availability 0.15, device role 0.08, dependency impact 0.08,
historical failures 0.06, health 0.06, disk headroom 0.04, reboot burden 0.04,
compat hit 0.04. Buckets P1 >= 70, P2 >= 55, P3 >= 40. Weights persist on every
assessment row so scores are auditable after the fact.

**What keeps the AI part honest?**
The LLM provider is a mock that writes rationales ONLY from recorded Fact rows -
it literally cannot invent numbers, and empty fact sets escalate instead of
hallucinating. Every agent stage persists its evidence, output JSON, rationale,
and a DecisionRow including rejected alternatives. Swapping in a real provider
changes narrative quality, never decisions: all decisions come from the engine.

**How do you know it works?**
157 tests, plus a labeled evaluation harness: scenarios run in throwaway SQLite
sandboxes and assertions score observed behavior (halt ring position, executed
positions <= 1, RCA class observed, rollback rows present). Deterministic seeds
make failures reproducible.

**What would break first in production?**
The simulator boundary - real MDM telemetry has messier state machines than my
five-state model, and install outcomes would need real retry semantics. Also
single-node SQLite; I'd move to Postgres (driver already wired) and add a
scheduler for autonomous advancement.

## Deep-dive breadcrumbs

- Workflow enforcement: `backend/app/workflow/engine.py` (TRANSITIONS map,
  `_replan_without_transition`, emergency flow)
- Determinism trick: `app/engine/common.py::stable_ratio` - attribute-keyed
  sha256 floats replace runtime randomness everywhere
- The planner's cohort-rep logic: `app/engine/rollout_engine.py::plan_rings`
- RCA confirmation rule: `app/engine/rca.py::correlate_root_cause`
- Evaluation honesty: `app/evaluation.py::run_bad_patch_scenario`

## Things to admit proactively

No auth layer; mock-only LLM; create_all instead of Alembic; synchronous=OFF
SQLite tradeoff; JS untested. Each is in LIMITATIONS.md with the reason.
