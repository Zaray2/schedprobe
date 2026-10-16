"""Every test must declare which evidence standard it holds the code to.

A one-off migration that annotated 332 tests would rot the moment someone added a 333rd,
so the annotation is enforced rather than encouraged. The failure message names the tests
that are missing a tier and explains what the tiers mean, because the person who trips
this is usually writing a test and has not read ``tests/tiers.py``.

This file also asserts something about the distribution. That is unusual for a test and it
is deliberate: the distribution is the answer to a fair criticism of this repository - that
most of its tests verify the author's own declarations rather than the code's correctness -
and a claim like that should be checkable rather than asserted. The bounds are deliberately
loose. They are not a target to hit; they exist so that a future change which quietly moves
the suite towards self-reference has to do so in the open.
"""

from __future__ import annotations

import importlib
import pathlib
import unittest

from .tiers import (
    TIER_CONSISTENCY,
    TIER_CONTRACT,
    TIER_MEANING,
    TIER_ORACLE,
    TIERS,
    resolve_tier,
    tier,
)

# Floor for the tier that can actually falsify a belief. If this ever trips, it means the
# suite grew by adding tests that can only agree with themselves.
MIN_ORACLE_SHARE = 0.35
# Ceiling for the tier that can only confirm what the documentation already says.
MAX_CONSISTENCY_SHARE = 0.45


def collect(repo_root=None):
    """Yield ``(module_name, class_name, method_name, tier)`` for every test in the suite."""
    tests_dir = pathlib.Path(__file__).resolve().parent
    rows = []
    for path in sorted(tests_dir.glob("test_*.py")):
        module = importlib.import_module(f".{path.stem}", package=__package__)
        for name in dir(module):
            obj = getattr(module, name)
            if not isinstance(obj, type) or not issubclass(obj, unittest.TestCase):
                continue
            for method in dir(obj):
                if not method.startswith("test_"):
                    continue
                attributed = getattr(obj, method, None)
                if not callable(attributed):
                    continue
                rows.append((path.stem, name, method, resolve_tier(attributed, owner=obj)))
    return rows


@tier(TIER_CONSISTENCY)
class TestTierCoverage(unittest.TestCase):
    def test_every_test_declares_a_tier(self) -> None:
        missing = [
            f"{module}.{klass}.{method}"
            for module, klass, method, declared in collect()
            if declared is None
        ]
        self.assertEqual(
            missing,
            [],
            "these tests do not declare a tier. Add @tier(...) to the class (or to the "
            "method if it differs from its class):\n  "
            + "\n  ".join(missing)
            + "\n\ntiers are defined by what would have to change for the test to fail:\n"
            + "\n".join(f"  {name}: {TIER_MEANING[name]}" for name in TIERS),
        )

    def test_every_declared_tier_is_known(self) -> None:
        unknown = sorted({tier for *_, tier in collect() if tier is not None and tier not in TIERS})
        self.assertEqual(unknown, [], f"unknown tiers: {unknown}")

    def test_the_suite_still_contains_tests_that_can_falsify_a_belief(self) -> None:
        rows = collect()
        counts = {name: sum(1 for *_, tier in rows if tier == name) for name in TIERS}
        total = len(rows)
        self.assertGreater(total, 0, "no tests were collected - the walker is broken")
        oracle_share = counts[TIER_ORACLE] / total
        consistency_share = counts[TIER_CONSISTENCY] / total
        self.assertGreaterEqual(
            oracle_share,
            MIN_ORACLE_SHARE,
            f"only {oracle_share:.0%} of {total} tests have an independent oracle "
            f"(floor {MIN_ORACLE_SHARE:.0%}). Counts: {counts}",
        )
        self.assertLessEqual(
            consistency_share,
            MAX_CONSISTENCY_SHARE,
            f"{consistency_share:.0%} of {total} tests only check the code against its own "
            f"documentation (ceiling {MAX_CONSISTENCY_SHARE:.0%}). Counts: {counts}",
        )

    def test_a_method_can_override_its_class(self) -> None:
        # The resolution rule is load-bearing for readability: most classes are uniform,
        # and the one test that is not should be markable without splitting the class.

        @tier(TIER_ORACLE)
        class Sample(unittest.TestCase):
            def test_inherits(self) -> None:
                pass

            @tier(TIER_CONSISTENCY)
            def test_overrides(self) -> None:
                pass

        self.assertEqual(resolve_tier(Sample), TIER_ORACLE)
        # The owner has to be supplied for a plain function: a function object has no
        # back-pointer to its class, and looking for one via __class__ finds `function`.
        self.assertEqual(resolve_tier(Sample.test_inherits, owner=Sample), TIER_ORACLE)
        self.assertEqual(resolve_tier(Sample.test_overrides, owner=Sample), TIER_CONSISTENCY)
        # A bound method can find its own class, so the owner is optional there.
        self.assertEqual(resolve_tier(Sample().test_inherits), TIER_ORACLE)

    def test_an_unknown_tier_is_rejected_at_declaration_time(self) -> None:

        with self.assertRaises(ValueError):
            tier("looks-independent-to-me")

    def test_contract_tests_are_counted_too(self) -> None:
        # Not an assertion about quality - just that the middle tier is non-empty, so a
        # later refactor cannot silently reclassify interface promises as either extreme.
        rows = collect()
        self.assertTrue(
            any(tier == TIER_CONTRACT for *_, tier in rows),
            "no contract-tier tests found; the interface promises are untested",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
