"""Deterministic synthetic endpoint fleet generator.

Given (estate_size, seed) the produced fleet is byte-for-byte reproducible.
Cohorts are deliberately planted:
  * ~8% of warehouse-department endpoints carry warehouse-scanner-suite 7.3.1
    (below the KB-SIM-2026-002 compat floor of 7.4.2) -- the designed bad-patch
    exposure.
  * A slice of Windows devices runs av-edr-agent < 4.2.0 (av_conflict cohort).
  * Some executive laptops run dock-driver < 1.5.0 (driver_conflict cohort).
  * Retail back-office machines may run ledger-cli < 2.0.0 (app_crash cohort).
"""
from __future__ import annotations

import hashlib
import json
import random

SCANNER_APP = "warehouse-scanner-suite"
SCANNER_OLD_VERSION = "7.3.1"
SCANNER_NEW_VERSION = "7.5.1"

DEPARTMENT_PLANS: list[tuple[str, float]] = [
    ("retail-pos", 0.21),
    ("warehouse", 0.17),
    ("call-center", 0.17),
    ("engineering", 0.14),
    ("finance", 0.12),
    ("executives", 0.09),
    ("it-lab", 0.10),
]

ROLE_PLANS: dict[str, list[tuple[str, float, str]]] = {
    # role, weight, criticality
    "retail-pos": [("pos-terminal", 0.70, "critical"), ("store-server", 0.12, "critical"),
                   ("back-office", 0.18, "medium")],
    "warehouse": [("scanner-handheld", 0.62, "medium"), ("warehouse-server", 0.14, "high"),
                  ("dock-kiosk", 0.24, "medium")],
    "call-center": [("agent-ws", 0.90, "medium"), ("supervisor-ws", 0.10, "high")],
    "engineering": [("build-agent", 0.25, "critical"), ("dev-ws", 0.60, "medium"),
                    ("infra-server", 0.15, "critical")],
    "finance": [("analyst-ws", 0.80, "high"), ("finance-app-server", 0.20, "critical")],
    "executives": [("exec-laptop", 0.55, "high"), ("exec-desktop", 0.45, "high")],
    "it-lab": [("lab-box", 0.75, "low"), ("lab-server", 0.25, "low")],
}

ROLE_OS_PLANS: dict[str, list[tuple[str, float, str]]] = {
    # os, weight, build string
    "pos-terminal": [("windows-11-23h2", 0.75, "22631.4037"), ("windows-10-22h2", 0.25, "19045.4046")],
    "store-server": [("windows-server-2022", 0.60, "20348.2402"), ("windows-server-2019", 0.40, "17763.5576")],
    "back-office": [("windows-11-23h2", 0.70, "22631.4037"), ("windows-10-22h2", 0.30, "19045.4046")],
    "scanner-handheld": [("windows-10-22h2", 0.90, "19045.4046"), ("windows-11-23h2", 0.10, "22631.4037")],
    "warehouse-server": [("windows-server-2019", 0.70, "17763.5576"), ("windows-server-2022", 0.30, "20348.2402")],
    "dock-kiosk": [("windows-10-22h2", 0.60, "19045.4046"), ("windows-11-23h2", 0.40, "22631.4037")],
    "agent-ws": [("windows-10-22h2", 0.55, "19045.4046"), ("windows-11-23h2", 0.45, "22631.4037")],
    "supervisor-ws": [("windows-11-23h2", 0.80, "22631.4037"), ("windows-10-22h2", 0.20, "19045.4046")],
    "build-agent": [("ubuntu-22.04", 0.50, "22.04.3"), ("rhel-9", 0.30, "9.3.0"),
                    ("windows-server-2022", 0.20, "20348.2402")],
    "dev-ws": [("macos-14", 0.35, "23C64"), ("ubuntu-22.04", 0.30, "22.04.3"),
               ("rhel-9", 0.15, "9.3.0"), ("windows-11-23h2", 0.20, "22631.4037")],
    "infra-server": [("windows-server-2022", 0.40, "20348.2402"), ("ubuntu-22.04", 0.35, "22.04.3"),
                     ("rhel-9", 0.25, "9.3.0")],
    "analyst-ws": [("windows-11-23h2", 0.85, "22631.4037"), ("windows-10-22h2", 0.15, "19045.4046")],
    "finance-app-server": [("windows-server-2022", 0.60, "20348.2402"), ("windows-server-2019", 0.40, "17763.5576")],
    "exec-laptop": [("macos-14", 0.55, "23C64"), ("windows-11-23h2", 0.45, "22631.4037")],
    "exec-desktop": [("windows-11-23h2", 0.80, "22631.4037"), ("macos-14", 0.20, "23C64")],
    "lab-box": [("windows-10-22h2", 0.25, "19045.4046"), ("windows-11-23h2", 0.25, "22631.4037"),
                ("ubuntu-22.04", 0.25, "22.04.3"), ("rhel-9", 0.15, "9.3.0"), ("macos-14", 0.10, "23C64")],
    "lab-server": [("windows-server-2019", 0.35, "17763.5576"), ("windows-server-2022", 0.30, "20348.2402"),
                   ("ubuntu-22.04", 0.20, "22.04.3"), ("rhel-9", 0.15, "9.3.0")],
}

HARDWARE: dict[str, tuple[tuple[float, float], tuple[float, float], tuple[float, float]]] = {
    # role: ((disk_free_gb lo, hi), (ram lo, hi), (cpu_age lo, hi))
    "pos-terminal": ((8.0, 42.0), (8, 16), (3.0, 6.0)),
    "store-server": ((60.0, 420.0), (32, 128), (2.0, 5.0)),
    "back-office": ((28.0, 140.0), (8, 16), (2.0, 5.0)),
    "scanner-handheld": ((2.4, 14.0), (3, 6), (2.0, 4.0)),
    "warehouse-server": ((50.0, 380.0), (32, 96), (2.0, 5.0)),
    "dock-kiosk": ((6.0, 30.0), (4, 8), (3.0, 6.0)),
    "agent-ws": ((20.0, 110.0), (8, 16), (2.0, 5.0)),
    "supervisor-ws": ((24.0, 130.0), (8, 32), (1.0, 4.0)),
    "build-agent": ((40.0, 300.0), (16, 64), (1.0, 4.0)),
    "dev-ws": ((60.0, 340.0), (16, 64), (1.0, 3.0)),
    "infra-server": ((44.0, 320.0), (32, 96), (2.0, 5.0)),
    "analyst-ws": ((30.0, 180.0), (8, 32), (1.0, 4.0)),
    "finance-app-server": ((55.0, 400.0), (32, 128), (2.0, 5.0)),
    "exec-laptop": ((40.0, 220.0), (16, 32), (0.5, 3.0)),
    "exec-desktop": ((45.0, 240.0), (16, 32), (0.5, 3.0)),
    "lab-box": ((14.0, 120.0), (8, 32), (1.0, 6.0)),
    "lab-server": ((36.0, 260.0), (16, 64), (2.0, 6.0)),
}

HEALTH_RANGE: dict[str, tuple[int, int]] = {
    "pos-terminal": (52, 88), "store-server": (72, 96), "back-office": (58, 92),
    "scanner-handheld": (46, 86), "warehouse-server": (72, 95), "dock-kiosk": (48, 84),
    "agent-ws": (56, 92), "supervisor-ws": (60, 94), "build-agent": (74, 97),
    "dev-ws": (66, 96), "infra-server": (74, 97), "analyst-ws": (60, 93),
    "finance-app-server": (76, 98), "exec-laptop": (68, 96), "exec-desktop": (68, 96),
    "lab-box": (66, 95), "lab-server": (70, 96),
}

HOSTNAME_PREFIX = {
    "pos-terminal": "POS", "store-server": "STRSVR", "back-office": "BOFF",
    "scanner-handheld": "SCN", "warehouse-server": "WHSVR", "dock-kiosk": "KIOSK",
    "agent-ws": "CCWS", "supervisor-ws": "CCSUP", "build-agent": "BLD",
    "dev-ws": "DEV", "infra-server": "INFSVR", "analyst-ws": "FINWS",
    "finance-app-server": "FINSVR", "exec-laptop": "EXLAP", "exec-desktop": "EXDSK",
    "lab-box": "LAB", "lab-server": "LABSVR",
}


def _weighted_choice(rng: random.Random, options) -> str:
    total = sum(w for _, w, *_ in options)
    roll = rng.uniform(0, total)
    acc = 0.0
    for item in options:
        acc += item[1]
        if roll <= acc:
            return item[0]
    return options[-1][0]


def _software_for(role: str, os_name: str, rng: random.Random) -> list[dict]:
    sw: list[dict] = []
    if os_name.startswith("windows"):
        sw.append({"name": "office-suite", "version": f"6.2.{rng.randint(0, 4)}"})
        av_roll = rng.random()
        if av_roll < 0.03:
            sw.append({"name": "av-edr-agent", "version": "4.1.7"})
        elif av_roll < 0.11:
            sw.append({"name": "av-edr-agent", "version": "4.7.2"})
        else:
            sw.append({"name": "av-edr-agent", "version": f"5.{rng.randint(0, 3)}.0"})
        if rng.random() < 0.70:
            sw.append({"name": "vpn-client", "version": f"3.{rng.randint(0, 9)}.1"})
        if rng.random() < 0.40:
            ver = "8u301" if rng.random() < 0.5 else f"17.0.{rng.randint(8, 12)}"
            sw.append({"name": "java-runtime", "version": ver})
    if role == "pos-terminal":
        sw.append({"name": "point-of-sale-client", "version": f"4.8.{rng.randint(0, 6)}"})
    if role == "scanner-handheld":
        # Old-suite cohort is stamped later (see plant_warehouse_cohort).
        sw.append({"name": SCANNER_APP, "version": SCANNER_NEW_VERSION})
        fw = f"3.{rng.randint(2, 5)}.0"
        if rng.random() < 0.06:
            fw = f"3.1.{rng.randint(0, 4)}"
        sw.append({"name": "warehouse-scanner-firmware", "version": fw})
    if role == "back-office" and rng.random() < 0.30:
        sw.append({"name": "ledger-cli", "version": "1.9.4"})
    if role in ("store-server", "warehouse-server"):
        sw.append({"name": "inventory-service", "version": f"2.{rng.randint(0, 4)}.0"})
        sw.append({"name": "license-manager", "version": f"1.{rng.randint(4, 9)}.0"})
    if role == "finance-app-server":
        sw.append({"name": "ledger-core", "version": f"5.{rng.randint(0, 3)}.1"})
    if role == "build-agent":
        sw.append({"name": "build-toolchain", "version": f"3.{rng.randint(0, 8)}.0"})
        sw.append({"name": "artifact-broker", "version": "2.2.0"})
    if role == "dev-ws":
        sw.append({"name": "ide-suite", "version": f"2026.{rng.randint(1, 2)}"})
        sw.append({"name": "container-runtime", "version": f"1.{rng.randint(28, 34)}.2"})
    if role == "lab-box":
        if rng.random() < 0.4:
            sw.append({"name": "java-runtime", "version": "8u301"})
    if role in ("exec-laptop", "exec-desktop") and os_name == "windows-11-23h2":
        if rng.random() < 0.25:
            sw.append({"name": "dock-driver", "version": f"1.{rng.randint(2, 4)}.x"})
        else:
            sw.append({"name": "dock-driver", "version": "1.6.0"})
    return sw


def plant_warehouse_cohort(endpoints: list[dict]) -> int:
    """Stamp the designed bad-patch exposure: old scanner suite on ~8% of
    warehouse endpoints (always on windows-10-22h2 handhelds). Returns count."""
    warehouse = [e for e in endpoints if e["department"] == "warehouse"]
    k = max(1, round(0.08 * len(warehouse)))
    candidates = [
        e for e in warehouse
        if e["role"] == "scanner-handheld" and e["os"] == "windows-10-22h2"
    ]
    candidates.sort(key=lambda e: e["id"])
    planted = 0
    for e in candidates[:k]:
        for item in e["software"]:
            if item["name"] == SCANNER_APP:
                item["version"] = SCANNER_OLD_VERSION
                planted += 1
    return planted


def generate_fleet(estate_size: int = 2500, seed: int = 1337) -> list[dict]:
    """Generate the deterministic endpoint fleet."""
    rng = random.Random(seed)

    # Department sizes (largest-first remainder handling keeps totals exact).
    raw = [(name, share * estate_size) for name, share in DEPARTMENT_PLANS]
    counts = {name: int(v) for name, v in raw}
    assigned = sum(counts.values())
    order = [name for name, _ in sorted(raw, key=lambda kv: -(kv[1] % 1))]
    idx = 0
    while assigned < estate_size:
        counts[order[idx % len(order)]] += 1
        assigned += 1
        idx += 1

    endpoints: list[dict] = []
    seq = 0
    for dept, _share in DEPARTMENT_PLANS:
        n_dept = counts[dept]
        # Role split for this department.
        role_targets: list[str] = []
        for role, weight, _crit in ROLE_PLANS[dept]:
            role_targets.extend([role] * int(round(weight * n_dept)))
        while len(role_targets) < n_dept:
            role_targets.append(ROLE_PLANS[dept][0][0])
        rng.shuffle(role_targets)

        for role in role_targets:
            seq += 1
            crit = next(c for r, _w, c in ROLE_PLANS[dept] if r == role)
            os_name, build = None, None
            os_pick = _weighted_choice(rng, ROLE_OS_PLANS[role])
            build = next(b for o, _w, b in ROLE_OS_PLANS[role] if o == os_pick)
            os_name = os_pick

            (d_lo, d_hi), (r_lo, r_hi), (c_lo, c_hi) = HARDWARE[role]
            h_lo, h_hi = HEALTH_RANGE[role]
            health = rng.randint(h_lo, h_hi)
            cpu_age = round(rng.uniform(c_lo, c_hi), 1)
            if cpu_age > 5.0:
                health = max(20, health - 12)
            hist_failures = 0
            if health < 45:
                hist_failures = rng.randint(2, 6)
            elif health < 60:
                hist_failures = rng.randint(0, 3)
            else:
                hist_failures = rng.choice([0, 0, 0, 1])

            pr_roll = rng.random()
            if pr_roll < 0.80:
                pending_reboot_days = 0
            elif pr_roll < 0.95:
                pending_reboot_days = rng.randint(1, 20)
            else:
                pending_reboot_days = rng.randint(30, 90)

            disk_free = round(rng.uniform(d_lo, d_hi), 1)
            # Small tail of genuinely disk-constrained devices.
            if rng.random() < 0.02:
                disk_free = round(rng.uniform(1.2, 2.2), 1)

            flags: list[str] = []
            eol = os_name == "windows-10-22h2"
            if eol:
                flags.append("eol-os")
            if disk_free < 5.0:
                flags.append("low-disk")
            if pending_reboot_days > 30:
                flags.append("reboot-overdue")
            if health < 35:
                flags.append("health-critical")

            prefix = HOSTNAME_PREFIX[role]
            endpoints.append({
                "id": seq,
                "hostname": f"{prefix}-{seq:05d}",
                "os": os_name,
                "os_build": build,
                "role": role,
                "department": dept,
                "criticality": crit,
                "eol": eol,
                "disk_free_gb": disk_free,
                "ram_gb": round(float(rng.randint(int(r_lo * 10), int(r_hi * 10))) / 10.0, 1),
                "cpu_age_years": cpu_age,
                "health_score": health,
                "historical_patch_failures": hist_failures,
                "pending_reboot_days": pending_reboot_days,
                "compliance_flags": flags,
                "software": _software_for(role, os_name, rng),
            })

    # Hostnames must be unique even with shared prefixes across depts: they are,
    # because seq is global. Re-id sequentially to be safe.
    for i, ep in enumerate(endpoints, start=1):
        ep["id"] = i

    planted = plant_warehouse_cohort(endpoints)
    assert planted >= 1, "designed warehouse cohort failed to plant"
    return endpoints


def fleet_checksum(endpoints: list[dict]) -> str:
    payload = []
    for e in endpoints:
        payload.append(json.dumps(
            {k: e[k] for k in (
                "hostname", "os", "department", "role", "criticality",
                "health_score", "disk_free_gb")},
            sort_keys=True))
    return hashlib.sha256("\n".join(payload).encode("utf-8")).hexdigest()


def old_scanner_suite_rate(endpoints: list[dict]) -> float:
    """Fraction of WAREHOUSE endpoints carrying the incompatible old suite."""
    wh = [e for e in endpoints if e["department"] == "warehouse"]
    if not wh:
        return 0.0
    hits = 0
    for e in wh:
        for item in e["software"]:
            if item["name"] == SCANNER_APP and item["version"] == SCANNER_OLD_VERSION:
                hits += 1
                break
    return hits / len(wh)
