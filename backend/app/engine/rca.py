"""Failure classification + root-cause correlation for ring failures."""
from __future__ import annotations

from collections import Counter, defaultdict

from app.engine.applicability import get_software_version
from app.engine.common import version_lt


def classify_failures(failed_rows: list[dict]) -> dict[str, int]:
    """Map failure rows ({failure_class, error_detail}) to taxonomy counts."""
    counts: Counter = Counter()
    for row in failed_rows:
        cls = row.get("failure_class")
        if not cls:
            detail = (row.get("error_detail") or "").lower()
            if "disk" in detail:
                cls = "disk_space"
            elif "prereq" in detail:
                cls = "missing_prereq"
            else:
                cls = "partial_install"
        counts[cls] += 1
    return dict(counts)


def _presence(endpoints, app_name: str) -> tuple[int, set[str]]:
    hits = 0
    versions: set[str] = set()
    for e in endpoints:
        v = get_software_version(e, app_name)
        if v is not None:
            hits += 1
            versions.add(v)
    return hits, versions


def correlate_root_cause(
    failed_endpoints: list,
    succeeded_endpoints: list,
    patch_row,
    min_failed_rate: float = 0.6,
    max_ok_rate: float = 0.3,
) -> list[dict]:
    """Differential analysis: which installed application separates failed
    devices from succeeded ones?

    Strategy:
      1. Version-aware check of every CATALOG known_issue for this patch --
         the documented cohort should reproduce exactly on the failed set.
      2. Generic app-presence differential for undocumented causes.
    """
    if not failed_endpoints:
        return []
    n_fail = len(failed_endpoints)
    n_ok = len(succeeded_endpoints)
    hypotheses: list[dict] = []

    # --- 1. catalog-known issues, version aware -----------------------------
    for issue in getattr(patch_row, "known_issues", None) or []:
        def hits(eps):
            n = 0
            for e in eps:
                v = get_software_version(e, issue.app_name)
                if v is not None and version_lt(v, issue.version_below):
                    n += 1
            return n

        fail_hits = hits(failed_endpoints)
        ok_hits = hits(succeeded_endpoints) if n_ok else 0
        fail_rate_v = fail_hits / n_fail
        ok_rate_v = (ok_hits / n_ok) if n_ok else 1.0
        if fail_hits == 0:
            continue
        confirmed = fail_rate_v >= min_failed_rate and ok_rate_v <= max_ok_rate
        versions = Counter(
            v for v in (get_software_version(e, issue.app_name) for e in failed_endpoints)
            if v is not None and version_lt(v, issue.version_below)
        )
        dominant = versions.most_common(1)[0][0] if versions else ""
        hypotheses.append({
            "app_name": issue.app_name,
            "failed_presence_rate": round(fail_rate_v, 3),
            "ok_presence_rate": round(ok_rate_v, 3),
            "dominant_failing_version": dominant,
            "matches_catalog_known_issue": True,
            "catalog_version_below": issue.version_below,
            "confirmed_by_differential": confirmed,
            "confidence": 0.95 if confirmed else 0.55,
            "root_cause": (
                f"{issue.app_name} {dominant} matches catalog known incompatibility "
                f"(breaks below {issue.version_below}): {issue.description}"
            ),
            "recommended_action": (
                f"Exclude the affected {issue.app_name}-cohort from this campaign; "
                f"upgrade {issue.app_name} >= {issue.version_below} before re-exposing them."
            ),
        })

    # --- 2. generic presence differential (undocumented causes) -------------
    app_names: set[str] = set()
    for e in failed_endpoints:
        for item in getattr(e, "software", None) or []:
            app_names.add(item.get("name"))
    covered = {h["app_name"] for h in hypotheses}
    for app in sorted(app_names):
        if app in covered:
            continue
        fail_hits, _fv = _presence(failed_endpoints, app)
        ok_hits, _ov = _presence(succeeded_endpoints, app)
        fail_rate_v = fail_hits / n_fail
        ok_rate_v = (ok_hits / n_ok) if n_ok else 1.0
        if fail_rate_v >= min_failed_rate and ok_rate_v <= max_ok_rate:
            version_counts = Counter(
                v for v in (get_software_version(e, app) for e in failed_endpoints)
                if v is not None
            )
            dominant = version_counts.most_common(1)[0][0] if version_counts else ""
            confidence = min(0.85, 0.5 + 0.4 * (fail_rate_v - ok_rate_v))
            hypotheses.append({
                "app_name": app,
                "failed_presence_rate": round(fail_rate_v, 3),
                "ok_presence_rate": round(ok_rate_v, 3),
                "dominant_failing_version": dominant,
                "matches_catalog_known_issue": False,
                "catalog_version_below": None,
                "confirmed_by_differential": True,
                "confidence": confidence,
                "root_cause": (
                    f"{app} (dominant failing version {dominant}) present on "
                    f"{fail_rate_v:.0%} of failures vs {ok_rate_v:.0%} of successes; "
                    "no catalog entry yet -- suspected undocumented incompatibility."
                ),
                "recommended_action": (
                    f"Hold campaign; add a known-issue entry for {app}; exclude cohort."
                ),
            })

    hypotheses.sort(key=lambda h: (-int(h["matches_catalog_known_issue"]), -h["confidence"]))
    return hypotheses


def build_rca_records(db_rows_context, campaign_id: int, ring: str,
                      failed_endpoints: list, succeeded_endpoints: list, patch_row):
    """Produce RCARecord rows: per-class taxonomy plus correlated root cause."""
    from app.models import RCARecord

    failed_by_class: defaultdict[str, list] = defaultdict(list)
    for e, fclass in failed_endpoints:
        failed_by_class[fclass].append(e)

    records = []
    hypotheses = correlate_root_cause(
        [e for e, _ in failed_endpoints], succeeded_endpoints, patch_row
    )
    top = hypotheses[0] if hypotheses else None
    for fclass, eps in sorted(failed_by_class.items()):
        record = RCARecord(
            campaign_id=campaign_id, ring=ring, failure_class=fclass,
            affected_count=len(eps),
            root_cause=top["root_cause"] if top else "no distinguishing factor found",
            correlated_factor=dict(top) if top else {},
            confidence=top["confidence"] if top else 0.3,
            recommended_action=top["recommended_action"] if top else "manual investigation",
        )
        records.append(record)
    return records, hypotheses
