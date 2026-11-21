"""Deterministic synthetic patch catalog (~21 patches).

Includes the DESIGNED bad patch: KB-SIM-2026-002 (Windows 10 22H2 cumulative)
carries a publicly documented incompatibility with warehouse-scanner-suite
versions < 7.4.2 (app_crash). The fleet generator plants that old suite on
~8% of warehouse-department endpoints, so a correct rollout must surface the
failure in an early ring, halt before RING_3, and recommend exclusion/remediation.
"""
from __future__ import annotations

from datetime import date


def build_catalog() -> list[dict]:
    """Return catalog rows as plain dicts (persisted by the seeder)."""
    patches: list[dict] = []

    def add(
        patch_id,
        name,
        target_os,
        severity,
        release,
        cves=None,
        issues=None,
        reboot=True,
        disk_mb=1024,
        minutes=25,
        supersedes=None,
        prerequisites=None,
        superseded_by=None,
        policy="canary_prove",
        notes="",
    ):
        patches.append(
            {
                "patch_id": patch_id,
                "name": name,
                "target_os": target_os,
                "severity": severity,
                "reboot_required": reboot,
                "release_date": release,
                "typical_install_minutes": minutes,
                "disk_space_required_mb": disk_mb,
                "supersedes": supersedes or [],
                "prerequisites": prerequisites or [],
                "superseded_by": superseded_by,
                "at_risk_policy_default": policy,
                "notes": notes,
                "cves": [
                    {
                        "cve_id": c["cve_id"],
                        "cvss": c["cvss"],
                        "known_exploited": c.get("known_exploited", False),
                        "description": c.get("description", ""),
                    }
                    for c in (cves or [])
                ],
                "known_issues": [
                    {
                        "kind": i["kind"],
                        "app_name": i["app_name"],
                        "version_below": i["version_below"],
                        "failure_class": i["failure_class"],
                        "description": i.get("description", ""),
                    }
                    for i in (issues or [])
                ],
            }
        )

    d = date

    # --- Windows 11 23H2 -----------------------------------------------------
    add(
        "KB-SIM-2026-001", "2026-01 Cumulative Update for Windows 11 23H2",
        "windows-11-23h2", "critical", d(2026, 1, 13),
        cves=[
            {"cve_id": "CVE-SIM-2026-0001", "cvss": 9.8, "known_exploited": True,
             "description": "RPC remote code execution, exploited in the wild."},
            {"cve_id": "CVE-SIM-2026-0002", "cvss": 7.5, "known_exploited": False,
             "description": "Kernel information disclosure."},
        ],
        disk_mb=2048,
        notes="Monthly cumulative; supersedes all older Win11 cumulatives.",
    )
    add(
        "KB-SIM-2026-016", ".NET 8 Security Update for Windows 11 23H2",
        "windows-11-23h2", "moderate", d(2026, 2, 10),
        cves=[{"cve_id": "CVE-SIM-2026-0016", "cvss": 6.2}],
        reboot=False, disk_mb=800, minutes=15,
    )
    add(
        "KB-SIM-2026-020", "Out-of-Band Emergency Update for Windows 11 23H2",
        "windows-11-23h2", "critical", d(2026, 3, 3),
        cves=[{"cve_id": "CVE-SIM-2026-0020", "cvss": 9.1, "known_exploited": True,
               "description": "SMBclient wormable RCE; active exploitation."}],
        supersedes=["KB-SIM-2026-001"], disk_mb=2200,
        notes="Emergency OOB release superseding KB-SIM-2026-001.",
    )
    add(
        "KB-SIM-2026-019", "Firmware & Dock Driver Bundle for Windows 11",
        "windows-11-23h2", "low", d(2026, 2, 18),
        cves=[],
        issues=[{
            "kind": "driver", "app_name": "dock-driver", "version_below": "1.5.0",
            "failure_class": "driver_conflict",
            "description": "Dock driver < 1.5.0 enters boot loop after firmware flash.",
        }],
        disk_mb=512, minutes=30,
    )

    # --- Windows 10 22H2 (EOL-soon segment) ----------------------------------
    add(
        "KB-SIM-2025-091", "2025-12 Cumulative Update for Windows 10 22H2",
        "windows-10-22h2", "high", d(2025, 12, 9),
        cves=[{"cve_id": "CVE-SIM-2025-0917", "cvss": 7.8}],
        superseded_by="KB-SIM-2026-002", disk_mb=1800,
        notes="Superseded by KB-SIM-2026-002; kept for supersedence tracking.",
    )
    # THE DESIGNED BAD PATCH.
    add(
        "KB-SIM-2026-002", "2026-01 Cumulative Update for Windows 10 22H2",
        "windows-10-22h2", "critical", d(2026, 1, 13),
        cves=[
            {"cve_id": "CVE-SIM-2026-0003", "cvss": 9.8, "known_exploited": True,
             "description": "Print spooler remote code execution, actively exploited."},
            {"cve_id": "CVE-SIM-2026-0004", "cvss": 8.1, "known_exploited": False,
             "description": "TLS bypass in schannel."},
        ],
        supersedes=["KB-SIM-2025-091"], disk_mb=1900,
        issues=[{
            "kind": "app_version", "app_name": "warehouse-scanner-suite",
            "version_below": "7.4.2", "failure_class": "app_crash",
            "description": (
                "Warehouse scanner suite versions below 7.4.2 crash on launch "
                "after this cumulative update (scanner IPC handshake change)."
            ),
        }],
        notes=(
            "Designed bad patch: the documented scanner-suite incompatibility "
            "affects ~8% of warehouse endpoints in the seeded estate."
        ),
    )
    add(
        "KB-SIM-2026-010", "EDR Agent Component Update (Windows)",
        "windows-10-22h2", "moderate", d(2026, 2, 24),
        cves=[{"cve_id": "CVE-SIM-2026-0104", "cvss": 6.8}],
        issues=[{
            "kind": "av_agent", "app_name": "av-edr-agent", "version_below": "4.2.0",
            "failure_class": "av_conflict",
            "description": "EDR agent versions < 4.2.0 deadlock the filter driver on install.",
        }],
        reboot=False, disk_mb=600, minutes=12,
    )

    # --- Windows Server -------------------------------------------------------
    add(
        "KB-SIM-2026-003", "2026-01 Cumulative Update for Windows Server 2022",
        "windows-server-2022", "high", d(2026, 1, 13),
        cves=[{"cve_id": "CVE-SIM-2026-0005", "cvss": 8.8, "known_exploited": False}],
        disk_mb=2400, minutes=35,
    )
    add(
        "KB-SIM-2026-005", "Servicing Stack Update for Windows Server 2019",
        "windows-server-2019", "moderate", d(2025, 12, 9),
        cves=[], reboot=False, disk_mb=200, minutes=8,
        notes="Prerequisite for KB-SIM-2026-004.",
    )
    add(
        "KB-SIM-2026-004", "2026-01 Cumulative Update for Windows Server 2019",
        "windows-server-2019", "high", d(2026, 1, 13),
        cves=[{"cve_id": "CVE-SIM-2026-0006", "cvss": 8.4}],
        prerequisites=["KB-SIM-2026-005"], disk_mb=2600, minutes=40,
    )
    add(
        "KB-SIM-2026-017", "File Server Hotfix for Windows Server 2022",
        "windows-server-2022", "high", d(2026, 2, 10),
        cves=[{"cve_id": "CVE-SIM-2026-0017", "cvss": 7.1}],
        disk_mb=900, minutes=20,
    )

    # --- Linux ----------------------------------------------------------------
    add(
        "KB-SIM-2026-006", "Kernel Security Update (Ubuntu 22.04)",
        "ubuntu-22.04", "high", d(2026, 1, 20),
        cves=[{"cve_id": "CVE-SIM-2026-0007", "cvss": 7.8}],
        disk_mb=1200, minutes=18,
        notes="Clean reference patch used by the clean-campaign scenario.",
    )
    add(
        "KB-SIM-2026-007", "Kernel Security Update (RHEL 9)",
        "rhel-9", "high", d(2026, 1, 20),
        cves=[{"cve_id": "CVE-SIM-2026-0008", "cvss": 7.8}],
        disk_mb=1200, minutes=18,
    )
    add(
        "KB-SIM-2026-015", "OpenSSL Security Update (Ubuntu 22.04 / RHEL 9)",
        "ubuntu-22.04", "critical", d(2026, 2, 3),
        cves=[{"cve_id": "CVE-SIM-2026-0015", "cvss": 9.1, "known_exploited": True,
               "description": "Heap overflow in DTLS parsing, exploited."}],
        reboot=False, disk_mb=300, minutes=8,
    )
    add(
        "KB-SIM-2026-021", "OpenSSL Security Update (RHEL 9)",
        "rhel-9", "critical", d(2026, 2, 3),
        cves=[{"cve_id": "CVE-SIM-2026-0015", "cvss": 9.1, "known_exploited": True}],
        reboot=False, disk_mb=300, minutes=8,
    )
    add(
        "KB-SIM-2026-018", "Build Toolchain Security Update (Linux build agents)",
        "ubuntu-22.04", "moderate", d(2026, 2, 14),
        cves=[{"cve_id": "CVE-SIM-2026-0018", "cvss": 5.9}],
        reboot=False, disk_mb=700, minutes=15,
    )

    # --- macOS -----------------------------------------------------------------
    add(
        "KB-SIM-2026-008", "macOS 14.4 Security Response",
        "macos-14", "high", d(2026, 1, 27),
        cves=[{"cve_id": "CVE-SIM-2026-0009", "cvss": 8.2}],
        disk_mb=3500, minutes=30,
    )

    # --- Cross-platform application patches -------------------------------------
    add(
        "KB-SIM-2026-009", "Java Runtime 8 Update (all platforms)",
        "windows-11-23h2", "moderate", d(2026, 2, 4),
        cves=[{"cve_id": "CVE-SIM-2026-0010", "cvss": 6.5}],
        issues=[{
            "kind": "app_version", "app_name": "ledger-cli", "version_below": "2.0.0",
            "failure_class": "app_crash",
            "description": "ledger-cli < 2.0.0 fails JNI binding with new JRE 8 update.",
        }],
        reboot=False, disk_mb=400, minutes=10,
    )
    add(
        "KB-SIM-2026-011", "VPN Client Update (Windows)",
        "windows-11-23h2", "low", d(2026, 1, 29),
        cves=[{"cve_id": "CVE-SIM-2026-0011", "cvss": 4.3}],
        reboot=False, disk_mb=350, minutes=10,
    )
    add(
        "KB-SIM-2026-012", "Point-of-Sale Client 4.9 Release",
        "windows-11-23h2", "high", d(2026, 2, 6),
        cves=[{"cve_id": "CVE-SIM-2026-0012", "cvss": 7.4}],
        disk_mb=650, minutes=15,
    )
    add(
        "KB-SIM-2026-013", "Office Suite February Security Patch",
        "windows-11-23h2", "moderate", d(2026, 2, 10),
        cves=[{"cve_id": "CVE-SIM-2026-0013", "cvss": 6.0}],
        reboot=False, disk_mb=1100, minutes=14,
    )
    add(
        "KB-SIM-2026-014", "Warehouse Scanner Suite 7.5 Platform Update",
        "windows-10-22h2", "moderate", d(2026, 2, 20),
        cves=[{"cve_id": "CVE-SIM-2026-0014", "cvss": 5.5}],
        issues=[{
            "kind": "app_version", "app_name": "warehouse-scanner-firmware",
            "version_below": "3.2.0", "failure_class": "partial_install",
            "description": "Scanner firmware < 3.2.0 half-applies the suite update.",
        }],
        reboot=False, disk_mb=500, minutes=12,
        notes="Remediating patch: upgrades the scanner suite past the 7.4.2 compat floor.",
    )

    return patches


# Identifiers used by scenarios/tests/ground truth.
BAD_PATCH_ID = "KB-SIM-2026-002"
CLEAN_PATCH_ID = "KB-SIM-2026-006"
SCANNER_APP = "warehouse-scanner-suite"
SCANNER_COMPAT_FLOOR = "7.4.2"
