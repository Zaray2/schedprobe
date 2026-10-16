"""Tests for the benchmark harness itself.

The benchmark is the evidence behind every performance claim in this repository, so it
needs the same scepticism as the code it measures. Three things are worth pinning:

* **the generated scenarios are what they claim to be** - the open-port count, the
  distribution across hosts and the /24 layout are read back from the scenario rather
  than trusted from its description string;
* **the aggregate metrics are arithmetic** - recall, precision and the comparison deltas
  are computed from countable things, and a bug there would quietly flatter a planner;
* **the harness does not resample its own results** - running the same case twice gives
  identical numbers, because the simulator is deterministic. If that ever stops being
  true, every published comparison becomes unreproducible.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from schedprobe.bench import (
    DEFAULT_PLANNERS,
    BenchmarkCase,
    BenchmarkResult,
    RepeatResult,
    all_cases,
    budget_sweep,
    compare,
    default_case,
    dense_sweep_scenario,
    repeat_case,
    run_benchmark,
    synthetic_case,
    write_results,
)
from schedprobe.errors import ConfigError
from schedprobe.models import PortState, segment_of

from .tiers import TIER_CONTRACT, TIER_ORACLE, tier


def _run(coro):
    return asyncio.run(coro)


@tier(TIER_ORACLE)
class TestGeneratedScenarios(unittest.TestCase):
    """``dense_sweep_scenario`` exists to give recall more than three samples."""

    def test_open_port_count_is_exact(self) -> None:
        scenario = dense_sweep_scenario(hosts=6, ports=64, opens_per_host=2, dead_fraction=0.0)
        truth = scenario.ground_truth(tuple(scenario.hosts), tuple(range(1, 65)))
        opens = [pair for pair, state in truth.items() if state is PortState.OPEN]
        self.assertEqual(len(opens), 6 * 2)

    def test_opens_are_spread_across_hosts_not_piled_on_one(self) -> None:
        # This is the property ``wide-sweep`` lacks, and the reason the claim about it had
        # no resolution: all three of its open ports sit on one host.
        scenario = dense_sweep_scenario(hosts=4, ports=64, opens_per_host=2, dead_fraction=0.0)
        per_host = {
            host: sum(1 for port in range(1, 65) if scenario.resolve(host, port) is PortState.OPEN)
            for host in scenario.hosts
        }
        self.assertTrue(all(count == 2 for count in per_host.values()), per_host)

    def test_first_opens_land_on_distinct_hosts(self) -> None:
        # Round-robin means the low port numbers - the ones a sweep reaches first - are
        # spread out, so a policy that finds one responsive host can be rewarded for
        # generalising.
        scenario = dense_sweep_scenario(hosts=5, ports=64, opens_per_host=1, dead_fraction=0.0)
        hosts_with_low_open = [
            host
            for host in scenario.hosts
            if any(scenario.resolve(host, port) is PortState.OPEN for port in range(1, 6))
        ]
        self.assertEqual(len(hosts_with_low_open), 5)

    def test_dead_fraction_makes_hosts_unreachable(self) -> None:
        scenario = dense_sweep_scenario(hosts=8, ports=32, opens_per_host=1, dead_fraction=0.5)
        dead = [host for host in scenario.hosts if scenario.is_unreachable(host)]
        self.assertEqual(len(dead), 4)
        for host in dead:
            self.assertIs(scenario.resolve(host, 22), PortState.FILTERED)

    def test_hosts_are_grouped_into_real_segments(self) -> None:
        # ``segment_of`` groups by /24. If every host landed in one segment the
        # segment-level policy would have nothing to observe.
        scenario = dense_sweep_scenario(hosts=16, ports=32, opens_per_host=1, hosts_per_segment=8)
        segments = {segment_of(host) for host in scenario.hosts}
        self.assertEqual(len(segments), 2)

    def test_addresses_survive_target_validation(self) -> None:
        # Regression: the first version built ``10.60.1`` and friends, which is not an IP
        # literal (three octets) and not a valid RFC 1123 name either, so building a scan
        # config raised TargetValidationError. Generating a scenario and *using* it are two
        # different code paths, and only the second one validates.
        scenario = dense_sweep_scenario(hosts=16, ports=32, opens_per_host=1)
        case = synthetic_case(scenario, tuple(range(1, 33)), 5000)
        case.validate()
        self.assertEqual(len(case.hosts), 16)

    def test_rejects_impossible_parameters(self) -> None:
        with self.assertRaises(ConfigError):
            dense_sweep_scenario(hosts=0)
        with self.assertRaises(ConfigError):
            dense_sweep_scenario(ports=0)
        with self.assertRaises(ConfigError):
            dense_sweep_scenario(opens_per_host=-1)
        with self.assertRaises(ConfigError):
            dense_sweep_scenario(dead_fraction=1.5)
        with self.assertRaises(ConfigError):
            dense_sweep_scenario(hosts_per_segment=0)


@tier(TIER_CONTRACT)
class TestCaseConstruction(unittest.TestCase):
    def test_synthetic_case_carries_the_scenario_hosts(self) -> None:
        scenario = dense_sweep_scenario(hosts=3, ports=16, opens_per_host=1)
        case = synthetic_case(scenario, (22, 80), 1000)
        self.assertEqual(case.hosts, tuple(sorted(scenario.hosts)))
        self.assertEqual(case.ports, (22, 80))
        case.validate()

    def test_default_case_picks_the_documented_port_ranges(self) -> None:
        self.assertEqual(len(default_case("wide-sweep", 1000).ports), 1024)
        self.assertEqual(len(default_case("segmented-sweep", 1000).ports), 64)
        self.assertEqual(len(default_case("healthy", 1000).ports), 7)

    def test_default_case_rejects_an_unknown_scenario(self) -> None:
        with self.assertRaises(ConfigError):
            default_case("nope", 1000)

    def test_case_validate_rejects_bad_input(self) -> None:
        with self.assertRaises(ConfigError):
            BenchmarkCase(scenario="healthy", hosts=(), ports=(80,), budget=100).validate()
        with self.assertRaises(ConfigError):
            BenchmarkCase(scenario="healthy", hosts=("10.0.0.1",), ports=(), budget=100).validate()
        with self.assertRaises(ConfigError):
            BenchmarkCase(scenario="healthy", hosts=("10.0.0.1",), ports=(80,), budget=0).validate()
        with self.assertRaises(ConfigError):
            BenchmarkCase(
                scenario="healthy",
                hosts=("10.0.0.1",),
                ports=(80,),
                budget=1,
                planners=("nope",),
            ).validate()
        with self.assertRaises(ConfigError):
            BenchmarkCase(
                scenario="healthy",
                hosts=("10.0.0.1",),
                ports=(80,),
                budget=1,
                prune_mode="sideways",
            ).validate()

    def test_all_cases_covers_every_builtin_scenario_and_validates(self) -> None:
        cases = all_cases(5000)
        self.assertTrue(cases)
        for case in cases:
            case.validate()
        self.assertEqual(
            {case.scenario for case in cases},
            {
                "healthy",
                "blackhole-segment",
                "segmented-filtered",
                "segmented-sweep",
                "mixed-lossy",
                "wide-sweep",
            },
        )


@tier(TIER_ORACLE)
class TestResultArithmetic(unittest.TestCase):
    def _result(self, **overrides) -> BenchmarkResult:
        base = {
            "planner": "adaptive",
            "scenario": "s",
            "seed": 1,
            "budget": 1000,
            "dispatched": 10,
            "cost_spent": 100,
            "open_found": 2,
            "open_total": 4,
            "closed_found": 1,
            "closed_total": 1,
            "filtered_found": 3,
            "filtered_total": 5,
            "undetermined": 0,
            "cost_of_filtered": 50,
            "time_to_first_open_cost": 10,
            "cost_to_full_recall": None,
            "confirms": 0,
            "pruned_segments": 0,
            "elapsed_s": 0.1,
            "run_id": "r",
            "evidence": "e",
        }
        base.update(overrides)
        return BenchmarkResult(**base)

    def test_recall_and_precision(self) -> None:
        result = self._result(open_found=3, open_total=4)
        self.assertAlmostEqual(result.recall, 0.75)
        self.assertAlmostEqual(result.precision, 1.0)

    def test_recall_of_a_scenario_with_no_opens_is_perfect(self) -> None:
        self.assertEqual(self._result(open_total=0, open_found=0).recall, 1.0)

    def test_false_open_destroys_precision(self) -> None:
        result = self._result(open_found=1, open_total=4, false_open=1)
        self.assertAlmostEqual(result.precision, 0.5)

    def test_precision_with_no_claims_is_perfect_by_convention(self) -> None:
        self.assertEqual(self._result(open_found=0, false_open=0).precision, 1.0)

    def test_compare_deltas_are_signed_and_relative_to_the_baseline(self) -> None:
        baseline = self._result(planner="fixed", open_found=2, open_total=4, cost_spent=100)
        better = self._result(planner="adaptive", open_found=4, open_total=4, cost_spent=50)
        deltas = compare([baseline, better], baseline="fixed")
        adaptive = deltas["adaptive"]
        self.assertAlmostEqual(adaptive["recall_delta_pp"], 50.0)
        self.assertAlmostEqual(adaptive["cost_delta_pct"], -50.0)
        # Each planner is compared against the baseline, never against its neighbour, so
        # the baseline itself does not appear as a zero row.
        self.assertNotIn("fixed", deltas)

    def test_compare_reports_a_missing_baseline_instead_of_inventing_one(self) -> None:
        # A silent fallback here would turn "no comparison possible" into "no difference",
        # which is the more dangerous of the two wrong answers.
        deltas = compare([self._result(planner="adaptive")], baseline="fixed")
        self.assertEqual(deltas, {"baseline_missing": "fixed"})


@tier(TIER_ORACLE)
class TestRepeatAggregation(unittest.TestCase):
    def test_repeat_result_summarises_the_spread(self) -> None:
        result = RepeatResult(planner="adaptive", seeds=(1, 2, 3), recalls=(0.25, 0.5, 0.75))
        self.assertAlmostEqual(result.mean_recall, 0.5)
        self.assertAlmostEqual(result.min_recall, 0.25)
        self.assertAlmostEqual(result.max_recall, 0.75)
        self.assertAlmostEqual(result.spread, 0.5)

    def test_repeat_result_handles_no_samples(self) -> None:
        result = RepeatResult(planner="adaptive", seeds=(), recalls=())
        self.assertEqual(result.mean_recall, 0.0)
        self.assertEqual(result.spread, 0.0)

    def test_repeat_result_serialises(self) -> None:
        payload = RepeatResult(planner="p", seeds=(1,), recalls=(0.5,)).to_dict()
        self.assertEqual(payload["planner"], "p")
        self.assertEqual(payload["seeds"], [1])
        self.assertEqual(payload["mean_recall"], 0.5)


@tier(TIER_ORACLE)
class TestHarnessIsReproducible(unittest.TestCase):
    """The simulator is deterministic, so the harness must be too."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="schedprobe-bench-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_same_case_twice_gives_identical_numbers(self) -> None:
        scenario = dense_sweep_scenario(hosts=3, ports=32, opens_per_host=1)
        case = synthetic_case(scenario, tuple(range(1, 33)), 4000)
        first = _run(run_benchmark(case, self.tmp / "a", scenario=scenario))
        second = _run(run_benchmark(case, self.tmp / "b", scenario=scenario))
        self.assertEqual(len(first), len(second))
        for left, right in zip(first, second, strict=True):
            self.assertEqual(left.planner, right.planner)
            self.assertEqual(left.recall, right.recall)
            self.assertEqual(left.cost_spent, right.cost_spent)
            self.assertEqual(left.open_found, right.open_found)
            self.assertEqual(left.dispatched, right.dispatched)

    def test_a_generated_scenario_needs_no_catalogue_entry(self) -> None:
        scenario = dense_sweep_scenario(hosts=2, ports=16, opens_per_host=1)
        case = synthetic_case(scenario, tuple(range(1, 17)), 3000)
        results = _run(run_benchmark(case, self.tmp / "gen", scenario=scenario))
        self.assertEqual({r.planner for r in results}, set(DEFAULT_PLANNERS))

    def test_repeat_case_groups_by_planner_and_covers_every_seed(self) -> None:
        scenario = dense_sweep_scenario(hosts=2, ports=16, opens_per_host=1)
        case = synthetic_case(scenario, tuple(range(1, 17)), 3000)
        repeats = _run(repeat_case(scenario, case, (1, 2), self.tmp / "rep"))
        self.assertEqual({r.planner for r in repeats}, set(DEFAULT_PLANNERS))
        for row in repeats:
            self.assertEqual(row.seeds, (1, 2))
            self.assertEqual(len(row.recalls), 2)

    def test_budget_sweep_covers_every_budget_and_planner(self) -> None:
        rows = _run(budget_sweep("healthy", (1000, 3000), self.tmp / "sweep"))
        budgets = {row.budget for row in rows}
        self.assertEqual(budgets, {1000, 3000})
        for row in rows:
            self.assertIn(row.planner, DEFAULT_PLANNERS)
            self.assertGreater(row.cost_spent, 0)


@tier(TIER_CONTRACT)
class TestWriteResults(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="schedprobe-benchw-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_writes_a_full_json_path(self) -> None:
        # Regression: the CLI used to append a fixed filename to whatever --save got, so
        # `bench --save out.json` wrote `out.json.json`.
        target = self.tmp / "nested" / "result.json"
        written = write_results(target, {"scenario": "s"})
        self.assertEqual(Path(written), target)
        self.assertTrue(target.is_file())
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(payload["scenario"], "s")

    def test_a_directory_gets_the_default_file_name(self) -> None:
        written = write_results(self.tmp / "dir", {"scenario": "s"})
        self.assertEqual(Path(written).name, "benchmark.json")
        self.assertTrue(Path(written).is_file())

    def test_creates_parent_directories(self) -> None:
        target = self.tmp / "deep" / "deeper" / "r.json"
        write_results(target, {"scenario": "s"})
        self.assertTrue(target.parent.is_dir())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
