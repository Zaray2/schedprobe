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

from schedprobe.models import PortState, ProbeResult, SegmentState, Verdict
from schedprobe.planners import build_planner


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


def build(planned: int, opens: int, closed: int, filtered: int) -> SegmentState:
    """Fold a run's worth of observations into one segment and return its state."""
    state = SegmentState(segment="10.0.0.0/24", hosts=("10.0.0.1",), planned=planned)
    for _ in range(opens):
        state.observe(probe(PortState.OPEN, confidence=0.95))
    for _ in range(closed):
        state.observe(probe(PortState.CLOSED, confidence=0.9))
    for _ in range(filtered):
        state.observe(probe(PortState.FILTERED, confidence=0.2))
    return state


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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
