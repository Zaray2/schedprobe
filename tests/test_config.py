"""Tests for configuration loading and validation.

Emphasis on *rejection*: a scan tool that silently repairs a bad config changes the
scope of a test without telling anybody, which is worse than refusing to start.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from schedprobe.config import (
    NetworkConfig,
    OutputConfig,
    PlannerConfig,
    SafetyConfig,
    ScanConfig,
    config_from_dict,
    config_to_dict,
    default_config,
    load_config,
)
from schedprobe.errors import ConfigError, TargetValidationError

from .tiers import TIER_CONTRACT, tier


@tier(TIER_CONTRACT)
class TestPlannerConfig(unittest.TestCase):
    def test_defaults_validate(self) -> None:
        PlannerConfig().validate()

    def test_unknown_planner_kind_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            PlannerConfig(kind="magic").validate()
        self.assertEqual(ctx.exception.code, "E_CONFIG")

    def test_budget_must_be_positive(self) -> None:
        for bad in (0, -1):
            with self.assertRaises(ConfigError):
                PlannerConfig(cost_budget=bad).validate()

    def test_reserved_ratio_bounds(self) -> None:
        with self.assertRaises(ConfigError):
            PlannerConfig(reserved_ratio=1.0).validate()
        with self.assertRaises(ConfigError):
            PlannerConfig(reserved_ratio=-0.1).validate()

    def test_prefix_len_bounds(self) -> None:
        PlannerConfig(prefix_len=8).validate()
        PlannerConfig(prefix_len=32).validate()
        for bad in (0, 7, 33):
            with self.assertRaises(ConfigError):
                PlannerConfig(prefix_len=bad).validate()

    def test_prune_mode_restricted(self) -> None:
        PlannerConfig(prune_mode="defer").validate()
        PlannerConfig(prune_mode="drop").validate()
        with self.assertRaises(ConfigError):
            PlannerConfig(prune_mode="delete").validate()

    def test_budget_slot_non_negative(self) -> None:
        PlannerConfig(budget_slot_ms=0).validate()
        with self.assertRaises(ConfigError):
            PlannerConfig(budget_slot_ms=-1).validate()


@tier(TIER_CONTRACT)
class TestNetworkConfig(unittest.TestCase):
    def test_timeout_ordering_enforced(self) -> None:
        with self.assertRaises(ConfigError):
            NetworkConfig(min_timeout_s=1.0, base_timeout_s=0.5, max_timeout_s=2.0).validate()
        with self.assertRaises(ConfigError):
            NetworkConfig(min_timeout_s=0.1, base_timeout_s=3.0, max_timeout_s=2.0).validate()

    def test_zero_timeout_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            NetworkConfig(min_timeout_s=0.0, base_timeout_s=0.0, max_timeout_s=1.0).validate()

    def test_concurrency_bounds(self) -> None:
        for bad in (0, -3, 4097):
            with self.assertRaises(ConfigError):
                NetworkConfig(concurrency=bad).validate()

    def test_negative_rate_limit_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            NetworkConfig(rate_limit_pps=-1.0).validate()


@tier(TIER_CONTRACT)
class TestOutputConfig(unittest.TestCase):
    def test_format_restricted(self) -> None:
        for good in ("table", "json", "jsonl", "csv"):
            OutputConfig(format=good).validate()
        with self.assertRaises(ConfigError):
            OutputConfig(format="xml").validate()

    def test_empty_out_dir_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            OutputConfig(out_dir="").validate()


@tier(TIER_CONTRACT)
class TestSafetyConfig(unittest.TestCase):
    def test_span_ratio_bounds(self) -> None:
        SafetyConfig(max_span_ratio=1.0).validate()
        with self.assertRaises(ConfigError):
            SafetyConfig(max_span_ratio=0.0).validate()
        with self.assertRaises(ConfigError):
            SafetyConfig(max_span_ratio=1.5).validate()


@tier(TIER_CONTRACT)
class TestScanConfig(unittest.TestCase):
    def test_default_config_validates(self) -> None:
        cfg = default_config()
        self.assertEqual(len(cfg.targets), 1)
        self.assertTrue(cfg.ports)

    def test_targets_normalized_and_deduplicated(self) -> None:
        cfg = default_config(targets=(" 127.0.0.1 ", "127.0.0.1"))
        self.assertEqual(cfg.targets, ("127.0.0.1",))

    def test_ports_deduplicated_preserving_order(self) -> None:
        cfg = default_config(ports=(443, 80, 443, 22))
        self.assertEqual(cfg.ports, (443, 80, 22))

    def test_bad_port_type_rejected(self) -> None:
        with self.assertRaises(TargetValidationError):
            default_config(ports=(80, "443"))  # type: ignore[arg-type]
        with self.assertRaises(TargetValidationError):
            default_config(ports=(True,))

    def test_port_range_enforced(self) -> None:
        with self.assertRaises(TargetValidationError):
            default_config(ports=(0,))
        with self.assertRaises(TargetValidationError):
            default_config(ports=(65536,))

    def test_empty_targets_rejected(self) -> None:
        cfg = ScanConfig(targets=(), ports=(80,))
        with self.assertRaises(TargetValidationError):
            cfg.validate()

    def test_empty_ports_rejected(self) -> None:
        cfg = ScanConfig(targets=("127.0.0.1",), ports=())
        with self.assertRaises(TargetValidationError):
            cfg.validate()

    def test_host_and_port_caps_enforced(self) -> None:
        cfg = ScanConfig(targets=("127.0.0.1",), ports=tuple(range(1, 20)))
        cfg.network.max_ports = 5
        with self.assertRaises(TargetValidationError):
            cfg.validate()

    def test_unknown_backend_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            default_config(backend="teleport")

    def test_span_ratio_guard(self) -> None:
        # ``max_span_ratio`` only bites when it is set below 1.0; at the default of 1.0
        # the guard is intentionally inert (declared scope == planned scope).
        cfg = ScanConfig(
            targets=("127.0.0.1",),
            ports=tuple(range(1, 101)),
            planner=PlannerConfig(cost_budget=10),
            safety=SafetyConfig(max_span_ratio=0.5),
        )
        with self.assertRaises(ConfigError):
            cfg.validate()

    def test_span_ratio_guard_is_inert_at_default(self) -> None:
        cfg = ScanConfig(
            targets=("127.0.0.1",),
            ports=tuple(range(1, 21)),
            planner=PlannerConfig(cost_budget=10),
        )
        cfg.validate()
        self.assertEqual(cfg.safety.max_span_ratio, 1.0)

    def test_roundtrip_to_from_dict(self) -> None:
        cfg = default_config(targets=("10.0.0.1", "10.0.0.2"), ports=(22, 80), run_label="lab")
        payload = config_to_dict(cfg)
        restored = config_from_dict(payload)
        self.assertEqual(restored.targets, cfg.targets)
        self.assertEqual(restored.ports, cfg.ports)
        self.assertEqual(restored.run_label, cfg.run_label)
        self.assertEqual(restored.planner.cost_budget, cfg.planner.cost_budget)

    def test_unknown_keys_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            config_from_dict({"targets": ["127.0.0.1"], "ports": [80], "typo_section": {}})
        with self.assertRaises(ConfigError):
            config_from_dict({"planner": {"magic": 1}})
        with self.assertRaises(ConfigError):
            config_from_dict({"planner": "not-a-table"})
        with self.assertRaises(ConfigError):
            config_from_dict({"network": "not-a-table"})
        with self.assertRaises(ConfigError):
            config_from_dict({"output": "not-a-table"})
        with self.assertRaises(ConfigError):
            config_from_dict({"safety": "not-a-table"})


@tier(TIER_CONTRACT)
class TestLoadConfig(unittest.TestCase):
    def test_load_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.toml"
            path.write_text(
                "targets = ['127.0.0.1']\nports = [22, 80]\nbackend = 'fake'\n"
                "[planner]\nkind = 'fixed'\ncost_budget = 123\n",
                encoding="utf-8",
            )
            cfg = load_config(path)
            self.assertEqual(cfg.planner.kind, "fixed")
            self.assertEqual(cfg.planner.cost_budget, 123)
            self.assertEqual(cfg.ports, (22, 80))

    def test_load_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text(
                json.dumps({"targets": ["127.0.0.1"], "ports": [80], "planner": {"seed": 7}}),
                encoding="utf-8",
            )
            cfg = load_config(path)
            self.assertEqual(cfg.planner.seed, 7)

    def test_overrides_win_and_leave_others_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.toml"
            path.write_text(
                "targets = ['127.0.0.1']\nports = [80]\n[planner]\ncost_budget = 100\n",
                encoding="utf-8",
            )
            cfg = load_config(path, {"planner.cost_budget": 500})
            self.assertEqual(cfg.planner.cost_budget, 500)
            self.assertEqual(cfg.planner.seed, 1337)

    def test_missing_file(self) -> None:
        with self.assertRaises(ConfigError):
            load_config("definitely-not-here.toml")

    def test_unsupported_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.yaml"
            path.write_text("targets: [127.0.0.1]\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_malformed_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.toml"
            path.write_text("this is not toml = = =\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_override_on_non_table_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.toml"
            path.write_text("targets = ['127.0.0.1']\nports = [80]\nplanner = 5\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path, {"planner.cost_budget": 10})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
