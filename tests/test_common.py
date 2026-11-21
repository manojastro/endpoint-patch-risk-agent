"""Unit tests: common deterministic helpers (hash ratio, versions, stop rules)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.common import (
    evaluate_stop_condition, failure_rate, parse_version, stable_ratio,
    version_gte, version_lt,
)


class TestStableRatio:
    def test_deterministic(self):
        assert stable_ratio("a:b:c") == stable_ratio("a:b:c")

    def test_range(self):
        vals = [stable_ratio(f"k{i}") for i in range(500)]
        assert all(0.0 <= v < 1.0 for v in vals)

    def test_spread(self):
        vals = [stable_ratio(f"k{i}") for i in range(200)]
        assert min(vals) < 0.2 and max(vals) > 0.8


class TestVersions:
    def test_parse(self):
        assert parse_version("7.4.2") == (7, 4, 2)

    def test_less_than(self):
        assert version_lt("7.3.1", "7.4.2")
        assert version_lt("7.3", "7.3.1")
        assert not version_lt("7.4.2", "7.4.2")  # floor is inclusive-safe

    def test_gte(self):
        assert version_gte("7.4.2", "7.4.2")
        assert version_gte("7.5", "7.4.2")


class TestFailureRate:
    def test_basic(self):
        assert failure_rate(2, 10) == 0.2
        assert failure_rate(1, 0) == 0.0


class TestStopCondition:
    def test_below_threshold_continues(self):
        halt, _ = evaluate_stop_condition("RING_1", 0.0499, 0.05, 0)
        assert halt is False

    def test_at_threshold_continues(self):
        # Strictly greater-than semantics: exactly at threshold continues.
        halt, _ = evaluate_stop_condition("RING_1", 0.05, 0.05, 0)
        assert halt is False

    def test_above_threshold_halts(self):
        halt, reason = evaluate_stop_condition("RING_1", 0.06, 0.05, 0)
        assert halt is True and "RING_1" in reason

    def test_critical_boot_failure_always_halts(self):
        halt, reason = evaluate_stop_condition("RING_3", 0.0, 0.02, 1)
        assert halt is True and "boot failure" in reason.lower()

    def test_zero_failures_continue(self):
        halt, _ = evaluate_stop_condition("RING_4", 0.0, 0.02, 0)
        assert halt is False
