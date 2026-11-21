# Endpoint Patch Risk & Safe Rollout Agent

A working FastAPI application that answers one operational question: **which patch,
on which endpoint groups, in what rollout order, and with what risk** - then proves
the answer by executing a staged ring rollout against a deterministic 2,500-endpoint
simulated fleet and autonomously halting when a patch misbehaves.

Everything runs offline. The LLM is a deterministic mock provider that writes
rationales only from recorded facts; the fleet, catalog, installs, and reboots are
all simulated deterministically from a fixed seed.

## Verified quickstart (Windows, Python 3.11)

```powershell
cd "D:\ai apps dump\claude code project\enterprise-agentic-ai-portfolio-batch-3\14-endpoint-patch-risk-agent"

python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# 1. Test suite - measured result: 157 passed, 0 failed (~26 s)
.venv\Scripts\python.exe -m pytest tests -q

# 2. Seed the world + run the designed bad-patch story (see DEMO.md)
.venv\Scripts\python.exe scripts\start_patch_campaign.py --reseed

# 3. Clean reference patch through all five rings
.venv\Scripts\python.exe scripts\run_clean_campaign_demo.py

# 4. Serve API + dark SecOps SPA on http://127.0.0.1:8014/
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8014
```

Docker:

```powershell
docker compose up --build          # http://localhost:8014
docker compose --profile postgres up   # optional Postgres instead of SQLite
```

Image build and container smoke test verified: `health: ok`, SPA served at `/`.

## What it does

| Capability | Where |
|---|---|
| Deterministic fleet simulator (2,500 endpoints, 7 departments, 8 OSes) | `backend/simulator/` |
| 22-patch catalog with CVEs, KEV flags, supersedence, prerequisites, PUBLIC known issues | `backend/simulator/generate_catalog.py` |
| 10 detector types (KEV exposure, EOL segments, drift, failed clusters, ...) | `backend/app/engine/detectors.py` |
| Weighted risk engine - 10 factors, P1-P4 buckets, weights persisted per assessment | `backend/app/engine/risk_engine.py` |
| Ring planner: lab -> canary -> pilot -> department -> broad, critical-tier deferral, at-risk cohort reps | `backend/app/engine/rollout_engine.py` |
| Autonomous stop conditions (>5% canary failure halts; any critical boot failure halts) | `backend/app/engine/common.py` + rollout engine |
| Version-aware root-cause analysis confirming catalog-known incompatibilities | `backend/app/engine/rca.py`, `agents/rca_agent.py` |
| Server-enforced 12-state workflow with approval gates + emergency fast-track | `backend/app/workflow/engine.py` |
| 12 registered agent tools, allow-listed, schema-validated, fully audited; no shell/subprocess tools | `backend/app/tools/` |
| Labeled ground-truth evaluation (15 checks) in a throwaway sandbox DB | `backend/app/evaluation.py`, `evaluation/ground_truth.json` |
| Prometheus metrics + KPI snapshots | `backend/app/metrics.py`, `metrics_kpi.py` |
| Vanilla-JS dark SecOps SPA served at `/` (zero CDN dependencies) | `frontend/` |

## The designed bad patch (the demo story)

`KB-SIM-2026-002` is a critical Windows 10 cumulative update carrying exploited CVEs.
The catalog publicly documents that it crashes `warehouse-scanner-suite < 7.4.2`,
and ~8% of the warehouse department still runs 7.3.1. Under the default
`canary_prove` policy the planner deliberately seats two scanner-cohort
representatives in the RING_1 canary. Measured behavior (2500-endpoint estate):

```
RING_0  succeeded        5 devices, 0 failures
RING_1  halted           6 devices, failure rate 50.00% > 5% stop threshold
RCA     warehouse-scanner-suite 7.3.1 < 7.4.2  [catalog confirmed, confidence 0.95]
        -> recommendation: exclude cohort; upgrade suite before re-exposing
Rollback restored 11 devices, post-rollback validation passed
Campaign final status: ROLLED_BACK  (never reached RING_3+)
```

The alternative `exclude` policy keeps at-risk cohorts out of every ring up front;
both policies are implemented and tested.

## Configuration

Environment variables (see `.env.example`): `DATABASE_URL` (SQLite default,
psycopg installed for Postgres), `ESTATE_SIZE=2500`, `SIM_SEED=1337`,
`LLM_MODE=mock`, `RING_FAILURE_THRESHOLDS=RING_0:0.10,RING_1:0.05,...`,
`CORS_ORIGINS`.

Same seed => byte-identical fleet and identical campaign outcomes.

## Documentation map

- [ARCHITECTURE.md](ARCHITECTURE.md) - layers, data model, decision flow
- [DEMO.md](DEMO.md) - narrated walkthroughs of both scenarios
- [EVALUATION.md](EVALUATION.md) - ground-truth harness and measured results
- [SECURITY.md](SECURITY.md) - tool gating, audit trail, threat-model posture
- [LIMITATIONS.md](LIMITATIONS.md) - what this POC does not do
- [docs/INTERVIEW_GUIDE.md](docs/INTERVIEW_GUIDE.md), [docs/RESUME_BULLETS.md](docs/RESUME_BULLETS.md)
