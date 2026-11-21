# Demo walkthroughs

Both demos run offline against the deterministic 2,500-endpoint world and persist
their campaigns so the SPA can display them.

## Scenario A - the designed bad patch (autonomous catch)

```powershell
.venv\Scripts\python.exe scripts\start_patch_campaign.py --reseed
```

Setup (all visible in the catalog, not hidden): `KB-SIM-2026-002` is a critical
Windows 10 22H2 cumulative update with two KEV-listed CVEs. The catalog carries a
PUBLIC known issue: it crashes `warehouse-scanner-suite` below version 7.4.2.
The fleet plants suite 7.3.1 on ~8% of warehouse endpoints.

Measured output (2500 estate):

```
Seeded world: 2501 endpoints, 22 patches, 9164 findings in 5.9s
CAMPAIGN: rollout of KB-SIM-2026-002 (policy=canary_prove)
Investigation: fleet=2501 eligible=557 KEV CVEs=5 P1 share=28
  plan RING_0: 5 devices   | plan RING_1: 6 devices (threshold 5%)
  note: Canary ~1% of eligible including 2 at-risk cohort representative(s)
Gate check OK (advance refused pre-approval): campaign execution requires an APPROVED deployment
RING_0  succeeded   devices=5  failed=0
RING_1  halted      devices=6  failed=3   rate=50.00% > threshold 5%
        *** AUTONOMOUS STOP ***
RCA:  warehouse-scanner-suite 7.3.1 < 7.4.2 [catalog confirmed] confidence=0.95
      recommendation: Exclude the affected cohort; upgrade >= 7.4.2 before re-exposing
Rollback: restored=11 devices, post-rollback validation passed=True
Final status: ROLLED_BACK
```

Why this is a fair demo: the incompatibility was knowable BEFORE rollout - it is
in the catalog - and the system uses that knowledge twice: proactively (seeding
the canary with at-risk cohort representatives so detection is deterministic) and
reactively (RCA confirms the catalog match with version-level evidence). The
campaign never reached RING_3+; the department wave and broad rings were skipped
and recorded as such.

## Scenario B - the clean reference patch (full progression)

```powershell
.venv\Scripts\python.exe scripts\run_clean_campaign_demo.py
```

`KB-SIM-2026-006` (Ubuntu kernel update, no known issues) walks all five rings
with zero breaches:

```
RING_0 succeeded devices=2   RING_1 succeeded devices=5
RING_2 succeeded devices=4   RING_3 succeeded devices=22
RING_4 succeeded devices=40
Final status: COMPLETED
```

## Seeing it in the browser

```powershell
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8014
# open http://127.0.0.1:8014/
```

- **Campaigns** tab shows both persisted campaigns (`demo-bad-patch` ROLLED_BACK,
  `demo-clean-patch` COMPLETED). Open #1 for the ring funnel with the red halted
  RING_1, the failure table (`app_crash`, error detail naming suite 7.3.1 < 7.4.2),
  the RCA card with the catalog-confirmed differential, and the live event feed.
- Create a new campaign from the UI ("Investigate & Plan"), request approval,
  approve, then Advance next ring - each advance appends events you can watch.
- **Patch Catalog** tab: click `KB-SIM-2026-002` for the compatibility matrix;
  warehouse x windows-10-22h2 shows `at_risk=7` (measured) - the scanner cohort -
  before anything ships.
- **Evaluation & Tools** tab: run the 15-check labeled evaluation in its sandbox
  and inspect the 12-tool registry with risk levels.

## Driving the same story over REST

```powershell
$base = "http://127.0.0.1:8014/api/v1"
$c = Invoke-RestMethod -Method Post -Uri "$base/campaigns" -ContentType "application/json" `
      -Body '{"patch_id":"KB-SIM-2026-002","at_risk_policy":"canary_prove"}'
Invoke-RestMethod -Method Post "$base/campaigns/$($c.id)/plan"
$a = Invoke-RestMethod -Method Post "$base/campaigns/$($c.id)/start"     # -> AWAITING_APPROVAL
Invoke-RestMethod -Method Post "$base/approvals/$($a.approval.id)/approve?decided_by=you"
Invoke-RestMethod -Method Post "$base/campaigns/$($c.id)/advance"        # repeat until stop/complete
```

Unapproved advance returns HTTP 403; illegal transitions return HTTP 409.
