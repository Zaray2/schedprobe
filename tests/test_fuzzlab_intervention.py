"""The guard that the FuzzLab failure taught, written down as a test.

Two research rounds were wasted on the same class of mistake: **an intervention that was not
running, measured as if it were.**

* Round one linked a prebuilt cJSON. A prebuilt shared library carries no instrumentation, so
  the fuzzer saw five edges and could not distinguish two seeds. Every arm looked identical
  and the "result" would have been noise.
* Round two loaded an AFL++ plugin. AFL++ printed
  `WARNING: Symbol 'afl_custom_fuzz' not found` and then never called the queue hook; five
  arms ran 10,000+ executions each and recorded 0-2 scheduling decisions.

Neither problem announced itself as an error. Both produced plausible numbers. What caught
them was *counting the intervention*, and what is missing without a test is anything that
forces the next person to do that.

So the rule these tests encode is:

    A campaign whose scheduler did not fire is INVALID, not "an arm that performed badly".

A zero here must be an error rather than a data point, because a zero indistinguishable from
"found nothing" is exactly how a broken harness turns into a published claim.
"""

from __future__ import annotations

import json
import unittest

from schedprobe.fuzzlab.arms import ARMS, arm_by_name
from schedprobe.fuzzlab.evidence_check import (
    InertInterventionError,
    InterventionEvidence,
    require_intervention_fired,
)

from .tiers import TIER_CONSISTENCY, TIER_ORACLE, tier


def evidence(**kwargs: object) -> InterventionEvidence:
    """Build an :class:`InterventionEvidence` with sane defaults for the assertions below."""
    base: dict[str, object] = {
        "arm": "full",
        "execs": 10000,
        "decisions": 10000,
        "admitted": 5000,
        "admit_ratio": 0.5,
    }
    base.update(kwargs)
    return InterventionEvidence(**base)  # type: ignore[arg-type]


@tier(TIER_ORACLE)
class TestInertInterventionIsAnError(unittest.TestCase):
    """The exact failure that cost two rounds, now impossible to report as a result."""

    def test_zero_decisions_over_ten_thousand_executions_is_rejected(self) -> None:
        # This is the measured shape of the broken round: 10,000+ executions, 0 decisions.
        with self.assertRaises(InertInterventionError) as ctx:
            require_intervention_fired(evidence(decisions=0), minimum_ratio=0.01)
        message = str(ctx.exception)
        self.assertIn("did not fire", message)
        self.assertIn("0", message)

    def test_two_decisions_in_ten_thousand_executions_is_rejected(self) -> None:
        # The shape after the missing symbol was fixed but the hook was still too coarse:
        # the intervention technically ran and could not possibly have mattered.
        with self.assertRaises(InertInterventionError):
            require_intervention_fired(evidence(decisions=2), minimum_ratio=0.01)

    def test_a_policy_that_fires_often_enough_is_accepted(self) -> None:
        report = require_intervention_fired(evidence(decisions=10000), minimum_ratio=0.01)
        self.assertAlmostEqual(report.decision_ratio, 1.0)

    def test_the_threshold_is_relative_not_absolute(self) -> None:
        # A short campaign is not penalised for having fewer decisions in absolute terms; what
        # matters is whether the scheduler participated in a meaningful share of executions.
        short = require_intervention_fired(evidence(execs=1000, decisions=200), minimum_ratio=0.01)
        self.assertAlmostEqual(short.decision_ratio, 0.2)
        with self.assertRaises(InertInterventionError):
            require_intervention_fired(evidence(execs=1000, decisions=0), minimum_ratio=0.01)

    def test_zero_executions_is_rejected_rather_than_dividing_by_zero(self) -> None:
        with self.assertRaises(InertInterventionError):
            require_intervention_fired(evidence(execs=0, decisions=0), minimum_ratio=0.01)

    def test_a_control_arm_that_admits_everything_still_counts_as_firing(self) -> None:
        # `all` exists so "having a plugin loaded" is not mistaken for a scheduling effect.
        # It must pass the firing check: it fires on every decision, it just always admits.
        report = require_intervention_fired(
            evidence(arm="all", decisions=10000, admitted=10000, admit_ratio=1.0),
            minimum_ratio=0.01,
        )
        self.assertEqual(report.admit_ratio, 1.0)

    def test_a_policy_that_never_admits_is_rejected(self) -> None:
        # Admitting nothing means the fuzzer is not running the policy, it is running nothing -
        # and in AFL++'s case an all-reject cycle makes the fuzzer exit early, which would
        # later be misread as "this arm found less".
        with self.assertRaises(InertInterventionError):
            require_intervention_fired(
                evidence(decisions=10000, admitted=0, admit_ratio=0.0), minimum_ratio=0.01
            )

    def test_the_report_is_serialisable_for_the_evidence_log(self) -> None:
        report = require_intervention_fired(evidence(), minimum_ratio=0.01)
        json.dumps(report.to_dict())


@tier(TIER_CONSISTENCY)
class TestTheArmsDeclareWhetherTheyIntervene(unittest.TestCase):
    """An arm that claims to test a policy must be an arm whose policy can fire."""

    def test_every_plugin_arm_declares_a_mode(self) -> None:
        for name in ("all", "static", "feedback", "full"):
            arm = arm_by_name(name)
            self.assertTrue(arm.uses_plugin, f"{name} should load the plugin")
            self.assertIsNotNone(arm.mode)

    def test_the_stock_arm_is_the_only_one_without_a_plugin(self) -> None:
        without = [arm.name for arm in ARMS if not arm.uses_plugin]
        self.assertEqual(without, ["stock"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
