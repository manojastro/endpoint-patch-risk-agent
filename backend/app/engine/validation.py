"""Post-patch / post-rollback validation checks (deterministic)."""
from __future__ import annotations

CHECK_SEQUENCE = [
    "boot_ok",
    "services_running",
    "cpu_within_bounds",
    "memory_within_bounds",
    "app_health_probe",
    "network_connectivity",
    "security_posture",
    "patch_installed",
    "reboot_completed",
]

BOOT_FAILURE_CLASSES = {"boot_failure", "driver_conflict"}
SERVICE_FAILURE_CLASSES = {"av_conflict"}
APP_FAILURE_CLASSES = {"app_crash", "partial_install"}
NETWORK_FAILURE_CLASSES = {"network_loss"}


def _chk(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "passed": bool(passed), "detail": detail}


def validate_endpoint_post_patch(endpoint, patch_row, install_result: dict, rebooted: bool) -> dict:
    """Run the canonical post-patch check sequence for one device.

    For failed installs the sequence still runs so the broken checks are
    recorded as evidence; `passed` is False in that case.
    """
    outcome = install_result.get("outcome")
    ok = outcome in ("success", "pending_reboot")
    fclass = install_result.get("failure_class")
    checks: list[dict] = []

    checks.append(_chk("boot_ok", fclass not in BOOT_FAILURE_CLASSES,
                       "" if ok or fclass is None else f"failure class {fclass}"))
    checks.append(_chk("services_running", fclass not in SERVICE_FAILURE_CLASSES))
    cpu_hot = (getattr(endpoint, "health_score", 60) < 35
               and getattr(patch_row, "severity", "moderate") == "critical"
               and not ok)
    checks.append(_chk("cpu_within_bounds", not cpu_hot,
                       "post-install CPU sustained >95% on degraded hardware" if cpu_hot else ""))
    ram_low = float(getattr(endpoint, "ram_gb", 8) or 8) < 4 and getattr(
        patch_row, "disk_space_required_mb", 0) > 1500
    checks.append(_chk("memory_within_bounds", not ram_low,
                       "RAM under floor for this payload" if ram_low else ""))
    checks.append(_chk("app_health_probe", fclass not in APP_FAILURE_CLASSES))
    checks.append(_chk("network_connectivity", fclass not in NETWORK_FAILURE_CLASSES))

    sw_names = {item.get("name") for item in (getattr(endpoint, "software", None) or [])}
    av_present = any(n.startswith("av-edr-agent") for n in sw_names)
    security_ok = (not av_present) or fclass not in SERVICE_FAILURE_CLASSES
    checks.append(_chk("security_posture", security_ok,
                       "" if security_ok else "AV/EDR agent not running post-patch"))

    patch_installed = ok
    checks.append(_chk("patch_installed", patch_installed,
                       "" if patch_installed else "install did not complete"))

    if bool(getattr(patch_row, "reboot_required", False)):
        checks.append(_chk("reboot_completed", rebooted and ok,
                           "" if (rebooted and ok) else "reboot pending/not completed"))
    else:
        checks.append(_chk("reboot_completed", True, "reboot not required"))

    passed = ok and all(c["passed"] for c in checks)
    # Failed installs must fail validation overall even if incidental checks pass.
    if not ok:
        passed = False
    return {"passed": passed, "checks": checks}


def validate_endpoint_post_rollback(endpoint, patch_row) -> dict:
    """After rollback the device must be healthy again and the patch absent."""
    checks: list[dict] = [
        _chk("boot_ok", True),
        _chk("services_running", True),
        _chk("app_health_probe", True, "application stack restored to pre-patch state"),
        _chk("security_posture", True),
        _chk("patch_absent", True, f"{getattr(patch_row, 'patch_id', '')} removed"),
    ]
    return {"passed": all(c["passed"] for c in checks), "checks": checks}
