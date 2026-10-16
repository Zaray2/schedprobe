"""Tests for the scheduler core: planner policies, the budget ledger, and the frontier.

These are the tests that matter most, because they pin the three claims the project makes:

* **the budget is a hard cap** - asserted from the evidence log itself
  (:class:`TestBudgetInvariant`), not from an internal counter;
* **the schedule is reproducible** - the same plan is produced twice
  (:class:`TestDeterminism`), and a replayed planner reaches the same frontier
  (:class:`TestFrontierReconstruction`);
* **the adaptive policy behaves as documented** - pruning, deferral, and the bounded
  confirmation pass each have their own case (:class:`TestAdaptivePolicy`).
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from schedprobe.backends.fake import FakeBackend, NetworkScenario, builtin_scenarios
from schedprobe.config import NetworkConfig, PlannerConfig, ScanConfig
from schedprobe.engine import ScanEngine
from schedprobe.errors import BackendError, ConfigError, EvidenceError
from schedprobe.evidence import read_records
from schedprobe.frontier import CostLedger, Frontier
from schedprobe.models import PortState, ProbeResult, Verdict, segment_of
from schedprobe.planners import (
    AdaptivePlanner,
    FixedLongTimeoutPlanner,
    FixedOrderPlanner,
    RandomOrderPlanner,
    build_planner,
)
from schedprobe.planners.base import ProbePlan, RttTracker, SegmentBook
from schedprobe.replay import replay_chain


def _config(hosts, ports, *, kind="adaptive", budget=50000, seed=1337, **planner_kwargs) -> ScanConfig:
    planner_kwargs.setdefault("prune_mode", "defer")
    config = ScanConfig(
        targets=tuple(hosts),
        ports=tuple(ports),
        backend="fake",
        planner=PlannerConfig(kind=kind, seed=seed, cost_budget=budget, **planner_kwargs),
        network=NetworkConfig(
            concurrency=16,
            base_timeout_s=0.6,
            min_timeout_s=0.15,
            max_timeout_s=3.0,
            max_hosts=64,
            max_ports=1024,
        ),
    )
    return config.validate()


def _run(config: ScanConfig, scenario: NetworkScenario | None = None, out_dir: str | Path = "runs-test"):
    scenario = scenario or builtin_scenarios()["blackhole-segment"]
    hosts = tuple(sorted(scenario.hosts))
    engine = ScanEngine(
        config,
        backend=FakeBackend(scenario=scenario, allow=list(config.targets) or list(hosts), config=config),
        out_dir=out_dir,
    )
    return asyncio.run(engine.run())


def _result(host: str, port: int, state: PortState, verdict: Verdict, confidence: float = 0.9) -> ProbeResult:
    return ProbeResult(
        host=host, port=port, state=state, verdict=verdict,
        cost_units=10, confidence=confidence, attempt=1,
    )


class TestSegmentBook(unittest.TestCase):
    def test_groups_hosts_by_prefix(self) -> None:
        book = SegmentBook(["10.0.1.5", "10.0.1.6", "10.0.2.5"], 24)
        self.assertEqual(sorted(book.segments), ["10.0.1.0/24", "10.0.2.0/24"])
        self.assertEqual(book.of("10.0.1.6").segment, "10.0.1.0/24")

    def test_observe_accumulates_counters(self) -> None:
        book = SegmentBook(["10.0.1.5"], 24)
        book.observe(_result("10.0.1.5", 80, PortState.OPEN, Verdict.CONNECTED))
        book.observe(_result("10.0.1.5", 81, PortState.CLOSED, Verdict.REFUSED))
        book.observe(_result("10.0.1.5", 82, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        state = book.of("10.0.1.5")
        self.assertEqual((state.open_count, state.closed_count, state.filtered_count), (1, 1, 1))
        self.assertEqual(state.planned, 3)
        self.assertEqual(book.total_cost(), 30)

    def test_consecutive_counters_reset(self) -> None:
        book = SegmentBook(["10.0.1.5"], 24)
        for _ in range(3):
            book.observe(_result("10.0.1.5", 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertEqual(book.of("10.0.1.5").consecutive_timeouts, 3)
        book.observe(_result("10.0.1.5", 81, PortState.CLOSED, Verdict.REFUSED))
        self.assertEqual(book.of("10.0.1.5").consecutive_timeouts, 0)

    def test_prune_marks_the_segment(self) -> None:
        book = SegmentBook(["10.0.1.5"], 24)
        book.prune("10.0.1.0/24", "test")
        self.assertTrue(book.of("10.0.1.5").pruned)
        self.assertEqual(book.of("10.0.1.5").prune_reason, "test")

    def test_snapshot_is_json_shaped(self) -> None:
        book = SegmentBook(["10.0.1.5"], 24)
        book.observe(_result("10.0.1.5", 80, PortState.OPEN, Verdict.CONNECTED))
        snapshot = book.snapshot()
        self.assertEqual(snapshot[0]["segment"], "10.0.1.0/24")
        self.assertIn("health_score", snapshot[0])


class TestHealthScore(unittest.TestCase):
    """The scoring rules are policy, so they get explicit expectations.

    An earlier revision rewarded *unanswered* segments (their low confidence made the
    score small) and the benchmark showed it spent a whole budget on a dead /24 while
    open ports sat unprobed. These tests encode the corrected ordering.
    """

    def _state(self, *, ports=(80, 443), **kwargs):
        from schedprobe.models import SegmentState

        return SegmentState(segment="10.0.0.0/24", ports=tuple(ports), **kwargs)

    def test_untested_segment_is_neutral_apart_from_coverage(self) -> None:
        # An untested segment sits at the neutral midpoint minus the coverage bonus,
        # which is what makes a fresh segment attractive without letting it outrank one
        # that has actually answered.
        score = self._state().health_score()
        self.assertLess(score, 0.5)
        self.assertGreater(score, 0.25)

    def test_answered_segment_ranks_before_untested(self) -> None:
        answered = self._state(open_count=1, planned=1, confidence_ema=0.99)
        self.assertLess(answered.health_score(), self._state().health_score())

    def test_filtered_only_segment_ranks_last(self) -> None:
        dead = self._state(filtered_count=3, planned=3, confidence_ema=0.45)
        self.assertGreater(dead.health_score(), self._state().health_score())
        self.assertGreater(dead.health_score(), self._state(open_count=1, planned=1).health_score())

    def test_coverage_bonus_favours_less_probed_segments(self) -> None:
        # Same observed quality, different amount of remaining work: the segment with
        # more unprobed pairs is more attractive. This is what stops the start-up batch
        # from emptying one segment before learning anything about the others.
        all_ports = (80, 443, 8080, 8443)
        # ``planned`` counts probes, ``ports`` is the segment's total pair count: the
        # coverage term uses (answered + filtered) / max(1, planned), so a segment with
        # the same quality but more unprobed pairs scores better.
        fresh = self._state(open_count=1, planned=1, confidence_ema=0.9, ports=all_ports)
        swept = self._state(open_count=1, planned=1, confidence_ema=0.9, ports=all_ports)
        self.assertEqual(fresh.health_score(), swept.health_score())
        further = self._state(open_count=1, planned=2, confidence_ema=0.9, ports=all_ports)
        self.assertGreater(further.health_score(), fresh.health_score())

    def test_timeout_penalty_scales_the_penalty(self) -> None:
        state = self._state(filtered_count=2, planned=4, confidence_ema=0.5, open_count=2)
        self.assertLess(state.health_score(timeout_penalty=0.0), state.health_score(timeout_penalty=4.0))

    def test_score_is_deterministic(self) -> None:
        state = self._state(filtered_count=1, planned=2, confidence_ema=0.6, open_count=1)
        self.assertEqual(state.health_score(), state.health_score())


class TestRttTracker(unittest.TestCase):
    def test_starts_at_base(self) -> None:
        tracker = RttTracker(0.6, 0.15, 3.0)
        self.assertEqual(tracker.current("h"), 0.6)

    def test_answered_probe_shrinks_the_timeout(self) -> None:
        tracker = RttTracker(0.6, 0.15, 3.0)
        tracker.observe("h", responded=True, cost_s=0.002)
        self.assertLess(tracker.current("h"), 0.6)

    def test_timeout_widens_the_timeout(self) -> None:
        tracker = RttTracker(0.6, 0.15, 3.0)
        tracker.observe("h", responded=False, cost_s=0.0)
        self.assertGreater(tracker.current("h"), 0.6)

    def test_bounds_are_respected(self) -> None:
        tracker = RttTracker(0.6, 0.15, 1.0)
        for _ in range(50):
            tracker.observe("h", responded=False, cost_s=0.0)
        self.assertLessEqual(tracker.current("h"), 1.0)
        for _ in range(50):
            tracker.observe("h2", responded=True, cost_s=0.0001)
        self.assertGreaterEqual(tracker.current("h2"), 0.15)

    def test_rejects_bad_alpha(self) -> None:
        for bad in (0.0, -0.1, 1.5):
            with self.assertRaises(ValueError):
                RttTracker(0.6, 0.15, 3.0, alpha=bad)

    def test_snapshot_is_sorted_and_stable(self) -> None:
        tracker = RttTracker(0.6, 0.15, 3.0)
        tracker.observe("b", responded=True, cost_s=0.01)
        tracker.observe("a", responded=False, cost_s=0.0)
        self.assertEqual(list(tracker.snapshot()), ["a", "b"])


class TestPlannerConstruction(unittest.TestCase):
    def test_unknown_planner_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            build_planner("nope", ["127.0.0.1"], (80,), PlannerConfig())

    def test_all_shipped_planners_build_and_plan(self) -> None:
        hosts, ports = ["127.0.0.1"], (80, 443)
        for kind in ("adaptive", "fixed", "random", "fixed-longtimeout"):
            planner = build_planner(kind, hosts, ports, PlannerConfig(kind=kind))
            pairs = planner.initialise()
            self.assertEqual(len(pairs), 2, kind)
            self.assertEqual(planner.live_count(), 2, kind)

    def test_plan_next_reports_a_plannable_pair(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80,), PlannerConfig())
        planner.initialise()
        plan = planner.plan_next(("10.0.0.1", 80))
        self.assertIsInstance(plan, ProbePlan)
        self.assertEqual(plan.pair, ("10.0.0.1", 80))
        self.assertGreater(plan.timeout_s, 0)
        self.assertFalse(plan.is_confirmation)

    def test_random_planner_is_seed_reproducible(self) -> None:
        hosts = [f"10.0.0.{i}" for i in range(1, 6)]
        first = build_planner("random", hosts, (80, 443), PlannerConfig(seed=7))
        second = build_planner("random", hosts, (80, 443), PlannerConfig(seed=7))
        self.assertEqual(first.initialise(), second.initialise())
        third = build_planner("random", hosts, (80, 443), PlannerConfig(seed=8))
        self.assertNotEqual(first.initialise() or [], third.initialise())

    def test_fixed_order_follows_input_order(self) -> None:
        hosts = ["10.0.0.2", "10.0.0.1"]
        planner = build_planner("fixed", hosts, (80, 443), PlannerConfig())
        self.assertEqual(planner.initialise()[:2], [("10.0.0.2", 80), ("10.0.0.2", 443)])

    def test_empty_frontier_yields_none(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80,), PlannerConfig())
        planner.initialise()
        planner.take(("10.0.0.1", 80))
        self.assertIsNone(planner.peek())


class TestAdaptivePolicy(unittest.TestCase):
    def _adaptive(self, hosts, ports, **kwargs) -> AdaptivePlanner:
        config = PlannerConfig(kind="adaptive", seed=1, cost_budget=100000, **kwargs)
        planner = AdaptivePlanner(hosts, ports, config)
        planner.initialise()
        return planner

    def test_prunes_a_segment_that_only_times_out(self) -> None:
        hosts = ["10.0.9.1", "10.0.9.2"]
        planner = self._adaptive(hosts, (80,), prune_after_consecutive_timeouts=2, prune_min_planned=2)
        for host in hosts:
            planner.take((host, 80))
            planner.observe(_result(host, 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        state = planner.book.of(hosts[0])
        self.assertTrue(state.pruned)
        self.assertIn("timeout", state.prune_reason)

    def test_defer_mode_keeps_the_pairs_probeable(self) -> None:
        hosts = ["10.0.9.1", "10.0.9.2"]
        planner = self._adaptive(
            hosts, (80, 443), prune_after_consecutive_timeouts=1, prune_min_planned=1,
            prune_mode="defer",
        )
        planner.take((hosts[0], 80))
        planner.observe(_result(hosts[0], 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertTrue(planner.book.of(hosts[0]).pruned)
        self.assertTrue(planner.book.of(hosts[0]).deferred)
        # A deferred pair is still in the frontier, just ranked behind everything alive.
        self.assertIn((hosts[1], 80), planner.live_pairs())

    def test_drop_mode_removes_the_pairs(self) -> None:
        hosts = ["10.0.9.1", "10.0.9.2"]
        planner = self._adaptive(
            hosts, (80, 443), prune_after_consecutive_timeouts=1, prune_min_planned=1,
            prune_mode="drop",
        )
        planner.take((hosts[0], 80))
        planner.observe(_result(hosts[0], 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertNotIn((hosts[1], 80), planner.live_pairs())

    def test_deferred_segment_scores_worse_than_any_live_one(self) -> None:
        dead_host, live_host = "10.0.9.1", "10.0.8.1"
        planner = self._adaptive(
            [dead_host, live_host], (80, 443),
            prune_after_consecutive_timeouts=1, prune_min_planned=1,
        )
        planner.take((dead_host, 80))
        planner.observe(_result(dead_host, 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertTrue(planner.book.of(dead_host).deferred)

        # The deferred segment keeps its pairs but they rank behind every live segment;
        # that is what 'defer' rather than 'drop' means. (The timed-out probe itself is
        # not re-queued for confirmation because the segment has answered nothing, so
        # another timeout would not be informative - see the confirmation gate.)
        self.assertEqual(planner.peek(), (live_host, 80))
        self.assertIn((dead_host, 443), planner.live_pairs())
        self.assertGreater(
            planner.base_score(dead_host, 443), planner.base_score(live_host, 80)
        )
        self.assertLess(planner.base_score(live_host, 80), planner.base_score(dead_host, 80))

    def test_confirmation_is_bounded(self) -> None:
        hosts, ports = ["10.0.0.1"], (80, 81)
        planner = self._adaptive(hosts, ports, confirm_min_attempts=1)
        pair = (hosts[0], 80)
        seen = 0
        for _ in range(10):
            planner.take(pair)
            planner.observe(_result(hosts[0], 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
            seen += 1
            if pair not in planner.live_pairs():
                break
        self.assertLessEqual(seen, 1 + 1 + 1, "initial probe plus the bounded retries")

    def test_confirmation_uses_a_longer_timeout(self) -> None:
        hosts = ["10.0.0.1"]
        planner = self._adaptive(hosts, (80, 443, 3306, 8080),
                                 confirm_timeout_multiplier=2.5, confidence_threshold=0.9)
        pair = (hosts[0], 8080)
        # Two promptly-answered probes first: the confirmation gate only retries where a
        # timeout contradicts the segment's established pattern.
        for port in (80, 443):
            planner.take((hosts[0], port))
            planner.observe(_result(hosts[0], port, PortState.CLOSED, Verdict.REFUSED))
        planner.take(pair)
        planner.observe(_result(hosts[0], 8080, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertIn(pair, planner.live_pairs())
        self.assertTrue(planner.reason_for(pair).startswith("confirm"))
        plan = planner.plan_next(pair)
        self.assertTrue(plan.is_confirmation)
        self.assertGreater(plan.timeout_s, planner.rtt.current(hosts[0]))

    def test_confirmation_is_skipped_in_a_segment_that_only_drops(self) -> None:
        # A segment that has answered nothing is not going to be enlightened by another
        # timeout, so the retry budget is not spent there. Without this gate the
        # benchmark showed recall dropping from 100% to 60% on `blackhole-segment`
        # because the retries consumed the sweep's budget.
        hosts = ["10.0.5.1"]
        planner = self._adaptive(hosts, (80,), confirm_max_drop_ratio=0.5)
        pair = (hosts[0], 80)
        planner.take(pair)
        planner.observe(_result(hosts[0], 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertNotIn(pair, planner.live_pairs())

    def test_confirmation_still_happens_after_a_host_has_answered(self) -> None:
        hosts = ["10.0.5.1"]
        planner = self._adaptive(hosts, (80, 443, 3306, 6379), confirm_max_drop_ratio=0.5)
        # Two promptly-answered ports put the drop ratio at 1/3, below the threshold.
        for port in (80, 443):
            planner.take((hosts[0], port))
            planner.observe(_result(hosts[0], port, PortState.CLOSED, Verdict.REFUSED))
        planner.take((hosts[0], 3306))
        planner.observe(_result(hosts[0], 3306, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertIn((hosts[0], 3306), planner.live_pairs())
        self.assertTrue(planner.reason_for((hosts[0], 3306)).startswith("confirm"))

    def test_unresponsive_segment_pruned_after_the_minimum_sample(self) -> None:
        hosts = [f"10.0.7.{i}" for i in range(1, 4)]
        planner = self._adaptive(hosts, (80,), prune_min_planned=3)
        for host in hosts:
            planner.take((host, 80))
            planner.observe(_result(host, 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        self.assertTrue(planner.book.of(hosts[0]).pruned)

    def test_healthy_segment_is_not_pruned(self) -> None:
        hosts = [f"10.0.6.{i}" for i in range(1, 4)]
        planner = self._adaptive(hosts, (80,))
        for index, host in enumerate(hosts):
            state = PortState.OPEN if index == 0 else PortState.CLOSED
            verdict = Verdict.CONNECTED if index == 0 else Verdict.REFUSED
            planner.take((host, 80))
            planner.observe(_result(host, 80, state, verdict))
        self.assertFalse(planner.book.of(hosts[0]).pruned)

    def test_describe_is_json_shaped(self) -> None:
        planner = self._adaptive(["10.0.0.1"], (80,))
        payload = planner.describe()
        self.assertEqual(payload["planner"], "adaptive")
        self.assertIn("pruning", payload)
        self.assertIn("confirmation", payload)

    def test_mark_heap_dirty_is_cleared_by_reheap(self) -> None:
        planner = self._adaptive(["10.0.0.1", "10.0.1.1"], (80, 443), prune_mode="drop",
                                 prune_after_consecutive_timeouts=1, prune_min_planned=1)
        planner.take(("10.0.0.1", 80))
        planner.observe(_result("10.0.0.1", 80, PortState.FILTERED, Verdict.TIMEOUT, 0.45))
        # ``peek`` rebuilds when dirty; the invariant check must then agree with it.
        planner.config.verify_heap = True
        head = planner.peek()
        planner.config.verify_heap = False
        self.assertIsNotNone(head)
        self.assertEqual(planner.score(*head), min(planner.score(*p) for p in planner.live_pairs()))


class TestPeekInvariant(unittest.TestCase):
    """``peek`` must return the minimum-scoring live pair, not merely a heap minimum."""

    def test_peek_returns_the_live_minimum_after_a_segment_rescale(self) -> None:
        hosts = [f"10.0.1.{i}" for i in range(1, 4)] + ["10.0.2.1"]
        ports = tuple(range(1, 8))
        config = PlannerConfig(kind="adaptive", seed=3, cost_budget=200000)
        planner = AdaptivePlanner(hosts, ports, config)
        planner.initialise()
        # Force a whole-segment rescale: observe an open port in the first /24.
        planner.take((hosts[0], 1))
        planner.observe(_result(hosts[0], 1, PortState.OPEN, Verdict.CONNECTED))
        head = planner.peek()
        live_min = min(planner.live_pairs(), key=lambda pair: planner.score(*pair))
        self.assertEqual(planner.score(*head), planner.score(*live_min))

    def test_verify_heap_flag_detects_nothing_on_a_healthy_planner(self) -> None:
        config = PlannerConfig(kind="adaptive", seed=3, cost_budget=200000, verify_heap=True)
        planner = AdaptivePlanner(["10.0.1.1", "10.0.2.1"], tuple(range(1, 6)), config)
        planner.initialise()
        for _ in range(4):
            pair = planner.peek()
            if pair is None:
                break
            planner.take(pair)
            planner.observe(_result(pair[0], pair[1], PortState.CLOSED, Verdict.REFUSED))
        self.assertIsNotNone(planner.peek())


class TestCostLedger(unittest.TestCase):
    def test_reserve_and_release(self) -> None:
        ledger = CostLedger(budget=1000)
        self.assertTrue(ledger.reserve(("h", 80), 600))
        self.assertEqual(ledger.reserved_total, 600)
        self.assertEqual(ledger.release(("h", 80)), 600)
        self.assertEqual(ledger.reserved_total, 0)

    def test_refuses_beyond_budget(self) -> None:
        ledger = CostLedger(budget=1000)
        self.assertTrue(ledger.reserve(("h", 80), 600))
        self.assertFalse(ledger.reserve(("h", 81), 600))
        self.assertEqual(len(ledger.reserved), 1)

    def test_settle_charges_actual_and_frees_the_lease(self) -> None:
        ledger = CostLedger(budget=1000)
        ledger.reserve(("h", 80), 600)
        ledger.settle(("h", 80), 4)
        self.assertEqual(ledger.spent, 4)
        self.assertEqual(ledger.reserved_total, 0)

    def test_committed_is_the_sum_of_both_ledgers(self) -> None:
        ledger = CostLedger(budget=1000)
        ledger.reserve(("h", 80), 300)
        ledger.settle(("h", 81), 100)
        ledger.reserve(("h", 82), 200)
        self.assertEqual(ledger.committed, 600)

    def test_snapshot_is_sorted(self) -> None:
        ledger = CostLedger(budget=10000)
        ledger.reserve(("10.0.0.2", 80), 100)
        ledger.reserve(("10.0.0.1", 80), 100)
        self.assertEqual(ledger.inflight_snapshot(), ["10.0.0.1:80", "10.0.0.2:80"])

    def test_may_dispatch_never_returns_negative_headroom(self) -> None:
        ledger = CostLedger(budget=0)
        self.assertFalse(ledger.may_dispatch(1))


class TestFrontierReconstruction(unittest.TestCase):
    def _frontier(self, planner, budget=100000):
        return Frontier(planner, CostLedger(budget=budget))

    def test_adopt_restores_the_in_flight_set(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80, 443), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner)
        frontier.adopt([("10.0.0.1", 80), ("10.0.0.1", 443)], {"10.0.0.1:80": 600, "10.0.0.1:443": 600})
        self.assertEqual(len(frontier.in_flight), 2)
        self.assertEqual(frontier.ledger.reserved_total, 1200)

    def test_adopt_refuses_an_unfundable_snapshot(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80, 443), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner, budget=100)
        with self.assertRaises(EvidenceError):
            frontier.adopt([("10.0.0.1", 80)], {"10.0.0.1:80": 600})

    def test_consume_settles_and_frees(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80,), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner)
        frontier.adopt([("10.0.0.1", 80)], {"10.0.0.1:80": 600})
        frontier.consume(("10.0.0.1", 80), 4)
        self.assertEqual(frontier.ledger.spent, 4)
        self.assertEqual(frontier.ledger.reserved_total, 0)
        self.assertEqual(frontier.in_flight, set())

    def test_admit_raises_when_the_engine_and_ledger_disagree(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80,), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner, budget=0)
        with self.assertRaises(EvidenceError) as ctx:
            frontier.admit(("10.0.0.1", 80), dispatched=True, extra=())
        self.assertIn("budget-rule divergence", str(ctx.exception))

    def test_admit_accepts_a_recorded_refusal(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80,), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner, budget=0)
        took, extra = frontier.admit(("10.0.0.1", 80), dispatched=False, extra=())
        self.assertFalse(took)
        self.assertEqual(extra, [])

    def test_admit_replays_recorded_extras(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80, 443, 8080), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner)
        took, extra = frontier.admit(
            ("10.0.0.1", 80),
            dispatched=True,
            extra=[{"pair": "10.0.0.1:443", "lease_ms": 600}],
        )
        self.assertTrue(took)
        self.assertEqual(extra, [("10.0.0.1", 443)])

    def test_admit_accepts_the_legacy_string_form(self) -> None:
        planner = build_planner("adaptive", ["10.0.0.1"], (80, 443), PlannerConfig())
        planner.initialise()
        frontier = self._frontier(planner)
        _took, extra = frontier.admit(("10.0.0.1", 80), dispatched=True, extra=["10.0.0.1:443"])
        self.assertEqual(extra, [("10.0.0.1", 443)])


class TestDeterminism(unittest.TestCase):
    """Same inputs must produce the same decisions - the project's central claim."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _decisions(self, run) -> list[tuple]:
        rows = []
        for record in read_records(run.evidence_path):
            if record.kind == "probe":
                decision = record.data.get("decision")
                dispatched = record.data["dispatched"]
                rows.append((
                    dispatched["host"], dispatched["port"], dispatched["reason"],
                    decision and (decision["host"], decision["port"]),
                    decision and round(float(decision["timeout_s"]), 6),
                ))
        return rows

    def test_two_identical_runs_make_identical_decisions(self) -> None:
        scenario = builtin_scenarios()["blackhole-segment"]
        hosts = tuple(sorted(scenario.hosts))
        config = _config(hosts, (22, 80, 443, 3306, 6379, 8080, 8443), budget=60000)
        first = _run(config, scenario, self.dir)
        second = _run(config, scenario, self.dir)
        self.assertEqual(self._decisions(first), self._decisions(second))
        self.assertEqual(first.summary.to_dict()["cost_spent"], second.summary.to_dict()["cost_spent"])

    def test_a_different_seed_changes_a_randomised_plan(self) -> None:
        scenario = builtin_scenarios()["healthy"]
        hosts = tuple(sorted(scenario.hosts))
        first = _run(_config(hosts, (22, 80), kind="random", seed=1, budget=20000), scenario, self.dir)
        second = _run(_config(hosts, (22, 80), kind="random", seed=2, budget=20000), scenario, self.dir)
        self.assertNotEqual(self._decisions(first), self._decisions(second))

    def test_replay_reproduces_the_schedule(self) -> None:
        scenario = builtin_scenarios()["segmented-filtered"]
        hosts = tuple(sorted(scenario.hosts))
        run = _run(_config(hosts, (22, 80, 443, 3306, 6379, 8080, 8443), budget=120000), scenario, self.dir)
        report = replay_chain(run.evidence_path)
        self.assertTrue(report.ok, report.divergences[:3])
        self.assertGreater(report.observations, 10)
        self.assertTrue(report.frontier_match)
        self.assertTrue(report.segments_match)

    def test_replay_reports_divergence_after_tampering(self) -> None:
        scenario = builtin_scenarios()["healthy"]
        hosts = tuple(sorted(scenario.hosts))
        run = _run(_config(hosts, (22, 80, 443), budget=20000), scenario, self.dir)
        lines = run.evidence_path.read_text(encoding="utf-8").splitlines()
        # Re-serialize one probe with a different observation cost, keeping the chain
        # digest consistent so only the *schedule* looks wrong.
        import json

        from schedprobe.util import canonical_json, sha256_hex

        payload = json.loads(lines[4])
        payload["data"]["observation"]["cost_units"] = 123456
        body = {key: value for key, value in payload.items() if key != "hash"}
        payload["hash"] = "sha256:" + sha256_hex(canonical_json(body))
        lines[4] = canonical_json(payload)
        for index in range(5, len(lines)):
            nxt = json.loads(lines[index])
            nxt["prev"] = payload["hash"] if index == 5 else json.loads(lines[index - 1])["hash"]
            body = {key: value for key, value in nxt.items() if key != "hash"}
            nxt["hash"] = "sha256:" + sha256_hex(canonical_json(body))
            lines[index] = canonical_json(nxt)
            payload = nxt
        run.evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        from schedprobe.evidence import verify_chain

        self.assertTrue(verify_chain(run.evidence_path).ok, "chain is internally consistent")
        report = replay_chain(run.evidence_path)
        self.assertFalse(report.ok)
        self.assertTrue(report.divergences)


class TestBudgetInvariant(unittest.TestCase):
    """The headline claim, asserted from the artifact rather than from a counter."""

    CASES = (
        ("healthy", (22, 80, 443), 5000),
        ("blackhole-segment", (22, 80, 443, 3306, 6379, 8080, 8443), 20000),
        ("blackhole-segment", (22, 80, 443, 3306, 6379, 8080, 8443), 150000),
        ("segmented-sweep", tuple(range(1, 65)), 30000),
        ("segmented-sweep", tuple(range(1, 65)), 150000),
        ("wide-sweep", (22, 80, 443), 60000),
    )

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_committed_cost_never_exceeds_the_budget(self) -> None:
        for name, ports, budget in self.CASES:
            with self.subTest(scenario=name, budget=budget):
                scenario = builtin_scenarios()[name]
                hosts = tuple(sorted(scenario.hosts))
                run = _run(_config(hosts, ports, budget=budget), scenario, self.dir)
                worst = 0
                for record in read_records(run.evidence_path):
                    if record.kind != "probe":
                        continue
                    committed = record.data["cost_spent"] + record.data["reserved_units"]
                    worst = max(worst, committed)
                    self.assertLessEqual(
                        committed, record.data["budget"],
                        f"seq {record.seq}: spent+reserved {committed} > budget {record.data['budget']}",
                    )
                self.assertGreater(worst, 0)

    def test_in_flight_never_exceeds_the_configured_concurrency(self) -> None:
        for name, ports, budget in self.CASES:
            with self.subTest(scenario=name, budget=budget):
                scenario = builtin_scenarios()[name]
                hosts = tuple(sorted(scenario.hosts))
                config = _config(hosts, ports, budget=budget)
                run = _run(config, scenario, self.dir)
                for record in read_records(run.evidence_path):
                    if record.kind != "probe":
                        continue
                    self.assertLessEqual(
                        len(record.data["inflight_pairs"]), config.network.concurrency
                    )

    def test_summary_agrees_with_the_log(self) -> None:
        scenario = builtin_scenarios()["blackhole-segment"]
        hosts = tuple(sorted(scenario.hosts))
        run = _run(_config(hosts, (22, 80, 443), budget=40000), scenario, self.dir)
        probes = [r for r in read_records(run.evidence_path) if r.kind == "probe"]
        self.assertEqual(run.summary.dispatched, len(probes))
        self.assertEqual(run.summary.pairs_touched, len(run.results))
        self.assertGreaterEqual(run.summary.dispatched, run.summary.pairs_touched)
        self.assertEqual(run.summary.cost_spent, probes[-1].data["cost_spent"])

    def test_budget_stop_reason_is_recorded(self) -> None:
        scenario = builtin_scenarios()["wide-sweep"]
        hosts = tuple(sorted(scenario.hosts))
        run = _run(_config(hosts, tuple(range(1, 100)), budget=2000), scenario, self.dir)
        stops = [r for r in read_records(run.evidence_path) if r.kind == "budget-stop"]
        self.assertEqual(len(stops), 1)
        self.assertIn(stops[0].data["reason"], {"no-headroom", "frontier-empty",
                                                "work-remaining", "concurrency-cap"})


class TestEngineSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_manifest_records_the_chain_and_verifies(self) -> None:
        scenario = builtin_scenarios()["healthy"]
        hosts = tuple(sorted(scenario.hosts))
        run = _run(_config(hosts, (22, 80, 443), budget=20000), scenario, self.dir)
        import json

        manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(manifest["chain_verified"])
        kinds = [r.kind for r in read_records(run.evidence_path)]
        self.assertEqual(manifest["evidence_records"], len(kinds))
        self.assertEqual(kinds.count("probe"), run.summary.dispatched)
        self.assertLessEqual(run.summary.pairs_touched, run.summary.dispatched)
        for expected in ("run-header", "config", "plan", "startup", "summary", "manifest"):
            self.assertIn(expected, kinds)
        from schedprobe.evidence import file_digest

        self.assertEqual(manifest["evidence_sha256"], file_digest(run.evidence_path)[0])
        self.assertEqual(manifest["probe_errors"], [])

    def test_backend_scope_guard_refuses_unlisted_hosts(self) -> None:
        scenario = builtin_scenarios()["healthy"]
        backend = FakeBackend(scenario=scenario, allow=["10.0.10.5"], config=None)
        from schedprobe.backends.base import ProbeRequest

        with self.assertRaises(BackendError):
            asyncio.run(backend.probe(ProbeRequest(host="10.0.10.6", port=22, timeout_s=0.1)))

    def test_run_id_is_unique_per_engine(self) -> None:
        scenario = builtin_scenarios()["healthy"]
        hosts = tuple(sorted(scenario.hosts))
        config = _config(hosts, (22,), budget=20000)
        first = ScanEngine(config, backend=FakeBackend(scenario, allow=list(hosts), config=config),
                           out_dir=self.dir)
        second = ScanEngine(config, backend=FakeBackend(scenario, allow=list(hosts), config=config),
                            out_dir=self.dir)
        self.assertNotEqual(first.run_id, second.run_id)

    def test_unknown_scenario_is_rejected(self) -> None:
        with self.assertRaises(BackendError):
            FakeBackend(scenario="not-a-scenario", allow=["127.0.0.1"])

    def test_cancel_before_run_produces_no_probes(self) -> None:
        scenario = builtin_scenarios()["healthy"]
        hosts = tuple(sorted(scenario.hosts))
        config = _config(hosts, (22, 80), budget=20000)
        engine = ScanEngine(config, backend=FakeBackend(scenario, allow=list(hosts), config=config),
                            out_dir=self.dir)
        engine.cancel()
        run = asyncio.run(engine.run())
        self.assertEqual(run.summary.dispatched, 0)
        self.assertTrue(run.chain_ok)


class TestBackendDeterminism(unittest.TestCase):
    def test_scenario_ground_truth_is_stable(self) -> None:
        scenario = builtin_scenarios()["blackhole-segment"]
        hosts = tuple(sorted(scenario.hosts))
        first = scenario.ground_truth(hosts, (22, 80))
        second = scenario.ground_truth(hosts, (22, 80))
        self.assertEqual(first, second)
        self.assertIn(PortState.FILTERED, set(first.values()))

    def test_costs_do_not_depend_on_probe_order(self) -> None:
        scenario = builtin_scenarios()["blackhole-segment"]
        hosts = tuple(sorted(scenario.hosts))
        config = _config(hosts, (22, 80), budget=50000)
        from schedprobe.backends.base import ProbeRequest

        async def probe_pair(host: str, port: int) -> int:
            backend = FakeBackend(scenario=scenario, allow=list(hosts), config=config)
            result = await backend.probe(ProbeRequest(host=host, port=port, timeout_s=0.6))
            return result.cost_units

        forward = asyncio.run(probe_pair(hosts[0], 22))
        asyncio.run(probe_pair(hosts[-1], 22))
        again = asyncio.run(probe_pair(hosts[0], 22))
        self.assertEqual(forward, again)

    def test_unreachable_host_is_filtered(self) -> None:
        scenario = NetworkScenario(name="dead", hosts={"10.9.9.9": {"unreachable": True}})
        backend = FakeBackend(scenario=scenario, allow=["10.9.9.9"], config=None)
        from schedprobe.backends.base import ProbeRequest

        result = asyncio.run(backend.probe(ProbeRequest(host="10.9.9.9", port=80, timeout_s=0.6)))
        self.assertEqual(result.state, PortState.FILTERED)
        self.assertEqual(result.verdict, Verdict.TIMEOUT)

    def test_unknown_host_is_undetermined_not_closed(self) -> None:
        scenario = NetworkScenario(name="empty", hosts={})
        backend = FakeBackend(scenario=scenario, allow=["10.9.9.9"], config=None)
        from schedprobe.backends.base import ProbeRequest

        result = asyncio.run(backend.probe(ProbeRequest(host="10.9.9.9", port=80, timeout_s=0.6)))
        self.assertEqual(result.state, PortState.UNDETERMINED)
        self.assertEqual(result.verdict, Verdict.UNRESOLVED)

    def test_loss_only_degrades_positive_evidence(self) -> None:
        scenario = NetworkScenario(
            name="lossy",
            hosts={"10.0.0.1": {"ports": {"80": "open", "81": "filtered"}, "default": "closed"}},
            loss_rate=0.5,
        )
        from schedprobe.backends.base import ProbeRequest

        backend = FakeBackend(scenario=scenario, allow=["10.0.0.1"], config=None)
        states = set()
        for _ in range(20):
            for port in (80, 81):
                result = asyncio.run(backend.probe(ProbeRequest(host="10.0.0.1", port=port,
                                                                timeout_s=0.6)))
                states.add((port, result.state))
        # Port 81 is filtered by construction: loss must never turn it into success.
        self.assertNotIn((81, PortState.OPEN), states)
        self.assertNotIn((81, PortState.CLOSED), states)
        # Port 80 may be reported undetermined (dropped) but never closed.
        self.assertNotIn((80, PortState.CLOSED), states)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
