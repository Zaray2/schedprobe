"""Tests for target/port parsing and the scope guard.

The security-relevant behaviour lives here: a target string must never reach a backend
before :func:`validate_targets` has classified it, and the classification must default to
*refusing* public space.
"""

from __future__ import annotations

import unittest

from schedprobe.config import SafetyConfig, default_config
from schedprobe.errors import TargetValidationError
from schedprobe.models import segment_of
from schedprobe.targets import (
    COMMON_PORTS,
    expand_targets,
    parse_ports,
    segment_map,
    validate_targets,
)


class TestParsePorts(unittest.TestCase):
    def test_single_and_list(self) -> None:
        self.assertEqual(parse_ports("80"), (80,))
        self.assertEqual(parse_ports("80,443,8080"), (80, 443, 8080))
        self.assertEqual(parse_ports(["80", "443"]), (80, 443))

    def test_range(self) -> None:
        self.assertEqual(parse_ports("80-83"), (80, 81, 82, 83))
        self.assertEqual(parse_ports("1-3,3-4"), (1, 2, 3, 4))

    def test_presets(self) -> None:
        self.assertEqual(parse_ports("top50"), tuple(COMMON_PORTS))
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_default_is_common_ports(self) -> None:
        self.assertEqual(parse_ports(None), tuple(COMMON_PORTS))

    def test_rejects_malformed(self) -> None:
        for bad in ("", "  ", "http", "80-", "-80", "80..90", "0", "65536", "1-99999"):
            with self.assertRaises(TargetValidationError, msg=bad):
                parse_ports(bad)

    def test_rejects_reversed_range(self) -> None:
        with self.assertRaises(TargetValidationError):
            parse_ports("100-50")

    def test_deduplicates_preserving_order(self) -> None:
        self.assertEqual(parse_ports("443,80,443"), (443, 80))


class TestExpandTargets(unittest.TestCase):
    def test_literal_and_hostname(self) -> None:
        self.assertEqual(expand_targets(["127.0.0.1"]), ("127.0.0.1",))
        self.assertEqual(expand_targets(["Example.INVALID."]), ("example.invalid",))

    def test_ipv6_literal_canonicalized(self) -> None:
        self.assertEqual(expand_targets(["::1"]), ("::1",))

    def test_cidr_expands_to_usable_hosts(self) -> None:
        self.assertEqual(expand_targets(["10.0.0.0/30"]), ("10.0.0.1", "10.0.0.2"))

    def test_cidr_bounds_enforced(self) -> None:
        with self.assertRaises(TargetValidationError):
            expand_targets(["10.0.0.0/8"])
        with self.assertRaises(TargetValidationError):
            expand_targets(["10.0.0.0/16"], max_hosts=10)

    def test_deduplicates(self) -> None:
        self.assertEqual(expand_targets(["10.0.0.1", "10.0.0.1"]), ("10.0.0.1",))

    def test_rejects_shell_metacharacters(self) -> None:
        for bad in (
            "127.0.0.1; id",
            "10.0.0.1&&whoami",
            "10.0.0.1|nc",
            "$(id)",
            "127.0.0.1`id`",
            "10.0.0.1\n10.0.0.2",
            "host name",
        ):
            with self.assertRaises(TargetValidationError, msg=bad):
                expand_targets([bad])

    def test_rejects_empty_and_non_string(self) -> None:
        with self.assertRaises(TargetValidationError):
            expand_targets([""])
        with self.assertRaises(TargetValidationError):
            expand_targets([None])  # type: ignore[list-item]

    def test_rejects_invalid_cidr(self) -> None:
        with self.assertRaises(TargetValidationError):
            expand_targets(["10.0.0.0/99"])
        with self.assertRaises(TargetValidationError):
            expand_targets(["300.1.1.1/24"])


class TestValidateTargets(unittest.TestCase):
    def test_loopback_allowed_by_default(self) -> None:
        safety = SafetyConfig()
        self.assertEqual(validate_targets(["127.0.0.1"], safety), ("127.0.0.1",))
        self.assertEqual(validate_targets(["::1"], safety), ("::1",))

    def test_private_allowed_by_default(self) -> None:
        self.assertEqual(validate_targets(["10.1.2.3"], SafetyConfig()), ("10.1.2.3",))
        self.assertEqual(validate_targets(["192.168.1.1"], SafetyConfig()), ("192.168.1.1",))

    def test_public_refused_by_default(self) -> None:
        with self.assertRaises(TargetValidationError) as ctx:
            validate_targets(["8.8.8.8"], SafetyConfig())
        self.assertIn("allow-public", str(ctx.exception))

    def test_public_allowed_when_opted_in(self) -> None:
        safety = SafetyConfig(allow_public=True)
        self.assertEqual(validate_targets(["8.8.8.8"], safety), ("8.8.8.8",))

    def test_private_refused_when_disabled(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_targets(["10.0.0.1"], SafetyConfig(allow_private=False))

    def test_loopback_refused_when_disabled(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_targets(["127.0.0.1"], SafetyConfig(allow_loopback=False))

    def test_hostname_toggle(self) -> None:
        safety = SafetyConfig(allow_dns=False)
        with self.assertRaises(TargetValidationError):
            validate_targets(["example.invalid"], safety)
        self.assertEqual(
            validate_targets(["example.invalid"], SafetyConfig(allow_dns=True)),
            ("example.invalid",),
        )

    def test_malformed_hostname_rejected(self) -> None:
        for bad in ("-bad.example", "bad-.example", "no-dot", "a" * 300, "exa mple.com"):
            with self.assertRaises(TargetValidationError, msg=bad):
                validate_targets([bad], SafetyConfig())

    def test_multicast_and_reserved_refused_even_with_public(self) -> None:
        safety = SafetyConfig(allow_public=True, allow_private=True)
        for bad in ("224.0.0.1", "0.0.0.0", "255.255.255.255"):
            with self.assertRaises(TargetValidationError, msg=bad):
                validate_targets([bad], safety)

    def test_empty_scope_refused(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_targets([], SafetyConfig())

    def test_max_hosts_enforced(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_targets(["10.0.0.1", "10.0.0.2"], SafetyConfig(), max_hosts=1)


class TestSegmentation(unittest.TestCase):
    def test_segment_of_ipv4(self) -> None:
        self.assertEqual(segment_of("10.1.2.3", 24), "10.1.2.0/24")
        self.assertEqual(segment_of("10.1.2.3", 16), "10.1.0.0/16")

    def test_segment_of_ipv6_floors_at_64(self) -> None:
        self.assertEqual(segment_of("2001:db8::1", 24), "2001:db8::/64")

    def test_hostnames_share_a_pseudo_segment(self) -> None:
        self.assertEqual(segment_of("example.invalid"), "dns")

    def test_segment_map_groups_and_sorts(self) -> None:
        grouped = segment_map(["10.0.2.5", "10.0.1.5", "10.0.1.6"], 24)
        self.assertEqual(list(grouped), ["10.0.1.0/24", "10.0.2.0/24"])
        self.assertEqual(grouped["10.0.1.0/24"], ("10.0.1.5", "10.0.1.6"))


class TestScanConfigScopeIntegration(unittest.TestCase):
    """The guard must fire through the config layer, not only when called directly."""

    def test_public_target_refused_by_default_config(self) -> None:
        with self.assertRaises(TargetValidationError):
            default_config(targets=("8.8.8.8",), ports=(80,))

    def test_cidr_target_accepted_and_scope_checked_after_expansion(self) -> None:
        # A CIDR spanning loopback only is fine; the guard runs over the expanded hosts.
        cfg = default_config(targets=("127.0.0.0/30",), ports=(80,))
        self.assertEqual(cfg.targets, ("127.0.0.0/30",))
        expanded = expand_targets(cfg.targets)
        self.assertEqual(expanded, ("127.0.0.1", "127.0.0.2"))

    def test_public_cidr_refused(self) -> None:
        with self.assertRaises(TargetValidationError):
            default_config(targets=("8.8.8.0/30",), ports=(80,))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
