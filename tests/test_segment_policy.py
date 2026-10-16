"""Does the segment score survive a segment that mixes a rich host with a quiet one?

A reviewer made a specific, checkable claim about ``SegmentState.health_score``: that a
/24 containing one host with a single open port is scored the same as a dead /24, so the
adaptive planner will deprioritise - and eventually prune - the one segment that is
actually worth probing.

The claim matters because the whole policy rests on this number. It is also the kind of
claim that cannot be settled by reading the formula and arguing: the formula has four
terms and the answer depends on which one dominates. So the tests below construct the
states by running probes, and read the score back.

Two cases, and they are deliberately different:

* **a mostly-filtered segment with one open port** - a live host behind a firewall, which
  is the common shape of a real engagement, and the one the reviewer is worried about;
* **a segment that has only ever timed out** - a dead /24, which should rank last.

If the first scores worse than the second, then aggregating liveness at /24 granularity
has thrown away the only signal that mattered, and the honest response is either to fix
the score or to say so in the docs. What is not acceptable is a README claim about
"segment health" that the score does not implement.
"""

from __future__ import annotations

import unittest

from schedprobe.models import (
    ANSWERED_CEILING,
    DEAD_FLOOR,
    UNTESTED_SCORE,
    PortState,
    ProbeResult,
    SegmentState,
    Verdict,
)
from schedprobe.planners import build_planner

from .tiers import TIER_CONSISTENCY, tier


def probe(
    state: PortState, *, confidence: float, host: str = "10.0.0.1", port: int = 80, cost: int = 600
) -> ProbeResult:
    verdict = {
        PortState.OPEN: Verdict.CONNECTED,
        PortState.CLOSED: Verdict.REFUSED,
        PortState.FILTERED: Verdict.TIMEOUT,
        PortState.UNDETERMINED: Verdict.UNRESOLVED,
    }[state]
    return ProbeResult(
        host=host,
        port=port,
        state=state,
        verdict=verdict,
        cost_units=cost,
        confidence=confidence,
        attempt=1,
    )


def build(
    planned: int,
    opens: int,
    closed: int,
    filtered: int,
    *,
    confidence_filtered: float = 0.2,
) -> SegmentState:
    """Fold a run's worth of observations into one segment and return its state."""
    state = SegmentState(segment="10.0.0.0/24", hosts=("10.0.0.1",), planned=planned)
    for _ in range(opens):
        state.observe(probe(PortState.OPEN, confidence=0.95))
    for _ in range(closed):
        state.observe(probe(PortState.CLOSED, confidence=0.9))
    for _ in range(filtered):
        state.observe(probe(PortState.FILTERED, confidence=confidence_filtered))
    return state


@tier(TIER_CONSISTENCY)
class TestMixedLivenessSegment(unittest.TestCase):
    """The reviewer's scenario, constructed from observations rather than asserted."""

    def test_a_segment_with_one_open_port_is_not_treated_as_dead(self) -> None:
        # 1 open port inside 999 timeouts: a live host behind a firewall.
        mixed = build(planned=1000, opens=1, closed=0, filtered=999)
        # A /24 that answered nothing at all.
        dead = build(planned=1000, opens=0, closed=0, filtered=1000)
        self.assertLess(
            mixed.health_score(),
            dead.health_score(),
            f"a segment holding an open port ({mixed.health_score()}) must rank ahead of a "
            f"segment that answered nothing ({dead.health_score()}); if it does not, the "
            "planner will prune the live segment first",
        )

    def test_a_segment_with_one_refusal_is_not_treated_as_dead(self) -> None:
        # A refusal is the cheapest possible proof that the host is alive. It costs one
        # RTT instead of one timeout, so it should be the strongest signal there is.
        refused = build(planned=1000, opens=0, closed=1, filtered=999)
        dead = build(planned=1000, opens=0, closed=0, filtered=1000)
        self.assertLess(
            refused.health_score(),
            dead.health_score(),
            "one refused connection is proof of life and must outrank a dead segment",
        )

    def test_the_ordering_survives_at_realistic_segment_sizes(self) -> None:
        # The published scenarios use 7 to 1024 ports per host. Check the property at
        # both ends rather than at one convenient size.
        for planned in (7, 64, 1024):
            with self.subTest(planned=planned):
                mixed = build(planned=planned, opens=1, closed=0, filtered=planned - 1)
                dead = build(planned=planned, opens=0, closed=0, filtered=planned)
                self.assertLess(
                    mixed.health_score(),
                    dead.health_score(),
                    f"at planned={planned}: live={mixed.health_score()} dead={dead.health_score()}",
                )

    def test_more_open_ports_still_ranks_better(self) -> None:
        # Monotonicity in the signal the model is supposed to reward.
        few = build(planned=1000, opens=1, closed=0, filtered=999)
        many = build(planned=1000, opens=10, closed=0, filtered=990)
        self.assertLess(many.health_score(), few.health_score())


@tier(TIER_CONSISTENCY)
class TestPlannerActuallyPrefersTheLiveSegment(unittest.TestCase):
    """The score is only interesting if the planner acts on it."""

    def _planner(self):
        config = type(
            "C",
            (),
            {
                "kind": "adaptive",
                "seed": 1,
                "cost_budget": 10**6,
                "prefix_len": 24,
                "prune_mode": "defer",
                "prune_after_consecutive_timeouts": 3,
                "prune_min_planned": 3,
                "confirm_min_attempts": 1,
                "confidence_threshold": 0.7,
                "confirm_max_drop_ratio": 0.5,
                "timeout_penalty": 1.0,
                "deferred_penalty": 2.0,
                "stale_window": 0,
                "budget_slot_ms": 600,
                "verify_heap": False,
            },
        )()
        return build_planner("adaptive", ["10.0.0.1", "10.0.1.1"], [80, 443], config)

    def test_peek_returns_the_live_segment_after_a_dead_one_is_exhausted(self) -> None:
        planner = self._planner()
        planner.initialise()
        # 10.0.0.0/24 answers; 10.0.1.0/24 only ever times out.
        live = planner.book.of("10.0.0.1")
        dead = planner.book.of("10.0.1.1")
        for state in (live, dead):
            state.planned = 2
        live.observe(probe(PortState.OPEN, confidence=0.95, host="10.0.0.1"))
        live.observe(probe(PortState.FILTERED, confidence=0.2, host="10.0.0.1", port=443))
        dead.observe(probe(PortState.FILTERED, confidence=0.2, host="10.0.1.1"))
        dead.observe(probe(PortState.FILTERED, confidence=0.2, host="10.0.1.1", port=443))
        planner.mark_heap_dirty()

        head = planner.peek()
        self.assertIsNotNone(head)
        self.assertEqual(
            head[0],
            "10.0.0.1",
            f"planner would probe {head} first; the segment that has answered must come first",
        )


@tier(TIER_CONSISTENCY)
class TestBandsAreDisjointOverTheWholeGrid(unittest.TestCase):
    """The contract, swept rather than sampled.

    A reviewer's follow-up was the right one: three constants and five hand-built cases
    describe the fix, but nothing enforces it. If someone later changes the penalty, the
    coverage bonus or the pruning thresholds, the bands could quietly overlap again and
    the sample cases might not be the ones that notice. The property is not "these five
    states are ordered", it is "for *every* reachable state, proof of life outranks a
    segment that has answered nothing" - so it is swept over a grid.

    The grid is deliberately coarse enough to run in a fraction of a second and wide
    enough to include the boundaries: a segment with a single reply among hundreds of
    timeouts, a segment with nothing but timeouts, and a segment that has not been probed.
    """

    def test_every_answered_state_outranks_every_dead_state(self) -> None:
        planned_values = (1, 2, 3, 7, 64, 257, 1024)
        answered_values = (1, 2, 5, 50, 500)
        # Confidences bracket what the engine actually records: 0.2 for a timeout, 0.9 for
        # a refusal, near 1.0 for a connect.
        confidence_values = (0.2, 0.45, 0.7, 0.95)
        timeout_penalties = (0.5, 1.0, 2.0)

        checked = 0
        worst_margin = None
        for planned in planned_values:
            for confidence in confidence_values:
                for penalty in timeout_penalties:
                    dead = build(
                        planned=planned,
                        opens=0,
                        closed=0,
                        filtered=planned,
                        confidence_filtered=0.2,
                    )
                    dead_score = dead.health_score(timeout_penalty=penalty)
                    for answered in answered_values:
                        if answered > planned:
                            continue
                        for kind in ("open", "closed"):
                            mixed = build(
                                planned=planned,
                                opens=answered if kind == "open" else 0,
                                closed=answered if kind == "closed" else 0,
                                filtered=planned - answered,
                                confidence_filtered=confidence,
                            )
                            mixed_score = mixed.health_score(timeout_penalty=penalty)
                            self.assertLess(
                                mixed_score,
                                dead_score,
                                f"planned={planned} answered={answered} kind={kind} "
                                f"conf={confidence} penalty={penalty}: "
                                f"answered={mixed_score} must be < dead={dead_score}",
                            )
                            margin = dead_score - mixed_score
                            if worst_margin is None or margin < worst_margin[0]:
                                worst_margin = (
                                    margin,
                                    f"planned={planned} answered={answered} kind={kind} "
                                    f"conf={confidence} penalty={penalty}",
                                )
                            checked += 1
        # A vacuous sweep would pass for the wrong reason.
        self.assertGreater(checked, 500, f"the grid only produced {checked} combinations")
        assert worst_margin is not None
        self.assertGreater(
            worst_margin[0],
            0.0,
            f"the tightest margin is {worst_margin[0]} at {worst_margin[1]}",
        )

    def test_an_answered_state_also_outranks_an_untested_one(self) -> None:
        # The other half of the ordering, and the one the docstring states explicitly:
        # "deliberately worse than any segment that has answered even one probe".
        untested = SegmentState(segment="10.0.0.0/24", hosts=("10.0.0.1",), planned=0)
        untested_score = untested.health_score()
        for planned in (1, 2, 7, 64, 1024):
            for answered in (1, 2, 5, 50):
                if answered > planned:
                    continue
                state = build(planned=planned, opens=answered, closed=0, filtered=planned - answered)
                self.assertLess(
                    state.health_score(),
                    untested_score,
                    f"planned={planned} answered={answered}: a segment that replied must "
                    f"outrank one that has not been probed",
                )

    def test_the_bands_are_ordered_as_documented(self) -> None:
        # Pin the actual constants so a change to them is a visible decision rather than a
        # silent drift. The values are part of the contract, not an implementation detail:
        # the ordering only holds because the bands do not overlap.
        self.assertLess(ANSWERED_CEILING, UNTESTED_SCORE)
        self.assertLess(UNTESTED_SCORE, DEAD_FLOOR)
        self.assertLessEqual(ANSWERED_CEILING, 0.3)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
