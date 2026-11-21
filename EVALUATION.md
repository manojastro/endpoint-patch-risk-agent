# Evaluation

## Design

The harness (`backend/app/evaluation.py`) runs each authored scenario inside a
**throwaway SQLite sandbox** (temp directory, own engine, deleted on exit), so
evaluation can never contaminate the serving world. Assertions score OBSERVED
behavior - campaign status, executed ring positions, RCA classes, rollback rows -
not internal flags.

Ground truth lives in `evaluation/ground_truth.json`:

1. `bad_patch_warehouse_scanner` - KB-SIM-2026-002 must be caught early:
   approval gate enforced, autonomous halt, stop at RING_0/RING_1, no execution
   of RING_3+, RCA class `app_crash`, rollback executed and validated,
   exclusion-or-remediation recommended.
2. `clean_patch_progression` - KB-SIM-2026-006 must complete all five rings with
   overall failure rate below 0.05 and finish COMPLETED.
3. `risk_engine_truths` - four crafted endpoint x patch pairs pinned to expected
   buckets: critical store-server with 12 dependents -> P1; medium workstation
   with pending reboot -> P2; scanner handheld carrying the incompatible AV
   version -> P3; healthy lab box -> P4. These pin bucket boundaries and the KEV /
   dependency / compat factors against gaming.

## Measured results (all checks passing)

| Estate size | Checks | Result | Duration |
|---|---|---|---|
| 300 | 15/15 | ALL PASS | ~2 s |
| 800 | 15/15 | ALL PASS | 3.0 s |

Bad-patch check details observed at estate 800:

```
[approval gate enforced]
[campaign halted autonomously]            status=FAILED
[stop at ring <= 1]                       max executed position=1
[no RING_3+ execution after stop]         positions=[0, 1]
[RCA class includes app_crash]            observed=['app_crash']
[rollback executed after halt]            campaign=ROLLED_BACK
[post-rollback validation passed]         rollbacks=1
[exclusion-or-remediation recommended]
```

Run it yourself:

```powershell
.venv\Scripts\python.exe -m pytest tests/test_evaluation.py -q      # asserts all_passed
# or over HTTP (persists an EvaluationRun row):
Invoke-RestMethod -Method Post "http://127.0.0.1:8014/api/v1/evaluation/run?estate_size=400"
```

Determinism: identical seeds produce identical fleets and outcomes, so a failing
check is always reproducible; the harness also asserts run-to-run equality in
`tests/test_evaluation.py::test_deterministic_across_runs`.

## Test suite

`157 passed, 0 failed` (~26 s) covering:

- engine math (stable_ratio determinism/range, version floors exclusive,
  stop-condition semantics including strict-greater and critical-boot precedence)
- applicability + eligibility (OS mismatch, superseded, prereqs, disk boundary,
  known-issue matching, cohort construction)
- risk engine (weights sum to 1.0, exact bucket boundaries, ground-truth pairs,
  KEV dominance delta == weight x factor span, disk factor saturation, weights
  persisted per assessment)
- simulator (fleet checksum determinism, catalog integrity, supersedence graph
  resolves, ~8% warehouse cohort rate within [0.05, 0.11], DB persistence)
- rollout planner (exact ring-size formulas on a 400-endpoint synthetic pool,
  ring disjointness, critical deferral, >=2 cohort reps in canary, exclude
  policy, emergency override admitting critical tier)
- install outcomes (disk/prereq/app_crash/av/driver classes, transient retry
  model forced via monkeypatched hash, pending_reboot only when required)
- validation sequences, failure taxonomy mapping, RCA correlation (catalog
  confirmation, unknown-cause fallback, non-separating apps ignored)
- detectors (KEV, EOL, exposure, config drift, severity ordering) + dependency
  graph blast radius
- agents (mock determinism, facts-only rationales, escalation on empty facts,
  evidence persistence)
- tools (exactly 12, no shell/exec tools, high-risk gated human-approval, schema
  rejection, audit rows for success AND failure, gate refusals)
- workflow (illegal transitions 409-class errors, approval/rejection gating,
  full happy path to COMPLETED, bad-patch halt -> rollback state restoration
  incl. patch states back to `applicable`, emergency fast-track flow)
- API surface (pagination/filters/validation errors, lifecycle via REST, metrics
  shape, Prometheus endpoint, static SPA served)

Known test-ordering note: modules share one seeded world DB for speed; modules
that need pristine state (API, workflow) reseed it explicitly at module start.
