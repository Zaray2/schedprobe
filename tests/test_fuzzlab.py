"""Tests for the FuzzLab measurement layer.

The fuzzing campaigns themselves need a Linux toolchain, a target and a lot of wall clock,
so they cannot run in this suite. What *can* run here is everything that turns a campaign into
a number, and that is where a research result is actually won or lost: a stats parser that
reads ``edges_found`` as a string, a deduplicator that counts one bug three times, or a budget
that is checked after the work is spent will each produce a table that looks like a finding.

So these tests hold the measurement code to the same standard as the scheduler it measures.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from schedprobe.fuzzlab import ARMS, arm_by_name
from schedprobe.fuzzlab.dedup import (
    CrashRecord,
    crash_signature,
    dedup_crashes,
    unique_defect_count,
)
from schedprobe.fuzzlab.model import (
    BudgetLedger,
    CampaignResult,
    Experiment,
    summarise_arm,
)
from schedprobe.fuzzlab.report import (
    render_arm_table,
    render_comparison,
    render_mechanism,
    write_results,
)
from schedprobe.fuzzlab.stats import parse_fuzzer_stats, read_fuzzer_stats

from .tiers import TIER_CONSISTENCY, TIER_ORACLE, tier

# Shaped like a real AFL++ fuzzer_stats file, including the padded key : value layout and the
# percentage that only `bitmap_cvg` carries.
FUZZER_STATS = """\
start_time        : 1700000000
last_update       : 1700000120
fuzzer_pid        : 4242
cycles_done       : 3
execs_done        : 12345
execs_per_sec     : 102.88
execs_ps_last_min : 100.10
corpus_count      : 41
corpus_varies     : 0
saved_crashes     : 2
saved_hangs       : 0
total_edges       : 1097
edges_found       : 218
bitmap_cvg        : 16.32%
run_time          : 120
max_depth         : 7
"""

ASAN_CRASH = """\
==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x55d0
WRITE of size 1 at 0x602000000014 thread T0
    #0 0x55d0c3f2a1b2 in parse_value /src/cjson/cJSON.c:1502:5
    #1 0x55d0c3f2a1b3 in parse_object /src/cjson/cJSON.c:2011:7
"""

ASAN_SEGV = """\
AddressSanitizer:DEADLYSIGNAL
==4242==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x55d0c3f2a1b2 in cJSON_Delete /src/cjson/cJSON.c:405:5
"""

ABORT_CRASH = """\
AddressSanitizer: ABRT
"""

UNPARSEABLE = """\
nothing useful here
"""


@tier(TIER_ORACLE)
class TestFuzzerStatsParsing(unittest.TestCase):
    """Numbers from the engine's own output file, typed correctly or not at all."""

    def test_core_fields_are_parsed_as_integers(self) -> None:
        stats = parse_fuzzer_stats(FUZZER_STATS, arm="full", seed=7)
        self.assertEqual(stats.execs_done, 12345)
        self.assertEqual(stats.edges_found, 218)
        self.assertEqual(stats.total_edges, 1097)
        self.assertEqual(stats.saved_crashes, 2)
        self.assertEqual(stats.corpus_count, 41)
        self.assertEqual(stats.cycles_done, 3)
        self.assertEqual(stats.arm, "full")
        self.assertEqual(stats.seed, 7)

    def test_the_percentage_field_is_parsed_rather_than_dropped(self) -> None:
        # `bitmap_cvg` is the only field with a trailing '%'. A naive int() would throw and
        # a naive except would silently record 0% coverage for every campaign.
        stats = parse_fuzzer_stats(FUZZER_STATS)
        self.assertAlmostEqual(stats.coverage_percent, 16.32, places=2)

    def test_rate_is_a_float(self) -> None:
        self.assertAlmostEqual(parse_fuzzer_stats(FUZZER_STATS).execs_per_sec, 102.88, places=2)

    def test_every_raw_key_is_kept(self) -> None:
        # A new AFL++ version adds fields; losing them silently would make an upgrade look
        # like a regression in coverage.
        stats = parse_fuzzer_stats(FUZZER_STATS)
        self.assertEqual(stats.raw["fuzzer_pid"], "4242")
        self.assertIn("execs_ps_last_min", stats.raw)

    def test_a_missing_field_does_not_raise(self) -> None:
        stats = parse_fuzzer_stats("execs_done : 5\n")
        self.assertEqual(stats.execs_done, 5)
        self.assertEqual(stats.edges_found, 0)

    def test_a_corrupt_value_does_not_raise(self) -> None:
        stats = parse_fuzzer_stats("execs_done : not-a-number\nedges_found : ???\n")
        self.assertEqual(stats.execs_done, 0)
        self.assertEqual(stats.edges_found, 0)

    def test_a_missing_stats_file_is_an_error_not_a_zeroed_record(self) -> None:
        # The failure mode this guards: a campaign that never ran being reported as
        # "0 edges found", which reads as "this arm performed badly" instead of
        # "the harness broke".
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            read_fuzzer_stats(Path(tmp) / "absent")

    def test_round_trips_through_dict(self) -> None:
        payload = parse_fuzzer_stats(FUZZER_STATS).to_dict()
        self.assertEqual(payload["edges_found"], 218)
        json.dumps(payload)  # must be serialisable for the JSON report


@tier(TIER_ORACLE)
class TestCrashSignatures(unittest.TestCase):
    """Defect counting must mean distinct faulting sites, not distinct crash files."""

    def test_heap_overflow_signature_includes_kind_and_top_frame(self) -> None:
        signature, kind, top = crash_signature(ASAN_CRASH)
        self.assertEqual(kind, "heap-buffer-overflow")
        self.assertIn("parse_value", top)
        self.assertIn("cJSON.c", top)
        self.assertTrue(signature.startswith("sha256:"))

    def test_line_and_column_are_stripped_so_a_rebuild_keeps_the_signature(self) -> None:
        # Same fault, different line number after an edit: still the same defect.
        moved = ASAN_CRASH.replace("cJSON.c:1502:5", "cJSON.c:1610:9")
        self.assertEqual(crash_signature(ASAN_CRASH)[0], crash_signature(moved)[0])

    def test_different_fault_sites_have_different_signatures(self) -> None:
        self.assertNotEqual(crash_signature(ASAN_CRASH)[0], crash_signature(ASAN_SEGV)[0])

    def test_deadlysignal_is_classified(self) -> None:
        _, kind, _ = crash_signature(ASAN_SEGV)
        self.assertIn(kind, ("DEADLYSIGNAL", "SEGV"))

    def test_abort_is_classified(self) -> None:
        _, kind, _ = crash_signature(ABORT_CRASH)
        self.assertIn(kind, ("ABRT", "DEADLYSIGNAL"))

    def test_unrecognisable_output_is_labelled_rather_than_collapsed(self) -> None:
        # Everything unknown must NOT share one signature, or a campaign of twenty unrelated
        # crashes would count as a single defect.
        signature, kind, _ = crash_signature(UNPARSEABLE)
        self.assertEqual(kind, "unknown")
        self.assertTrue(signature)

    def test_dedup_groups_by_signature(self) -> None:
        def record(name: str, output: str) -> CrashRecord:
            signature, kind, top = crash_signature(output)
            return CrashRecord("full", 1, Path(name), signature, kind, top, 16)

        first = record("a", ASAN_CRASH)
        second = record("b", ASAN_CRASH)
        third = record("c", ASAN_SEGV)
        grouped = dedup_crashes([first, second, third])
        self.assertEqual(len(grouped), 2)
        self.assertEqual(unique_defect_count([first, second, third]), 2)

    def test_dedup_of_nothing_is_zero_defects(self) -> None:
        self.assertEqual(unique_defect_count([]), 0)
        self.assertEqual(dedup_crashes([]), {})


@tier(TIER_ORACLE)
class TestBudgetLedger(unittest.TestCase):
    """The cap is checked before the work, never after it."""

    def test_charging_never_exceeds_the_limit(self) -> None:
        ledger = BudgetLedger(kind="seconds", limit=100)
        self.assertEqual(ledger.charge(60), 60)
        self.assertEqual(ledger.charge(60), 40)  # only 40 left
        self.assertEqual(ledger.spent, 100)
        self.assertTrue(ledger.exhausted())

    def test_would_exceed_is_available_before_spending(self) -> None:
        ledger = BudgetLedger(kind="execs", limit=10)
        ledger.charge(8)
        self.assertTrue(ledger.would_exceed(5))
        self.assertFalse(ledger.would_exceed(2))
        self.assertEqual(ledger.spent, 8, "checking must not spend")

    def test_remaining_never_goes_negative(self) -> None:
        ledger = BudgetLedger(kind="execs", limit=5)
        ledger.charge(99)
        self.assertEqual(ledger.remaining(), 0)


@tier(TIER_CONSISTENCY)
class TestArmDefinitions(unittest.TestCase):
    """The arms must differ only in the scheduler, or the comparison is of build config."""

    def test_every_arm_is_named_and_has_a_role(self) -> None:
        for arm in ARMS:
            self.assertTrue(arm.name)
            self.assertTrue(arm.role, f"{arm.name} has no stated role")

    def test_the_ablation_arms_disable_exactly_one_signal(self) -> None:
        # If an ablation arm left both signals on, the report could not attribute an effect.
        static = arm_by_name("static")
        feedback = arm_by_name("feedback")
        self.assertEqual(static.env["FUZZLAB_W_FEEDBACK"], "0.0")
        self.assertEqual(static.env["FUZZLAB_W_STATIC"], "1.0")
        self.assertEqual(feedback.env["FUZZLAB_W_STATIC"], "0.0")
        self.assertEqual(feedback.env["FUZZLAB_W_FEEDBACK"], "1.0")

    def test_the_stock_arm_loads_no_plugin(self) -> None:
        self.assertFalse(arm_by_name("stock").uses_plugin)

    def test_the_control_arm_loads_the_plugin_but_admits_everything(self) -> None:
        control = arm_by_name("all")
        self.assertTrue(control.uses_plugin)
        self.assertEqual(control.mode, "all")

    def test_unknown_arm_names_list_the_valid_ones(self) -> None:
        with self.assertRaises(KeyError) as ctx:
            arm_by_name("nope")
        self.assertIn("stock", str(ctx.exception))

    def test_arm_serialises(self) -> None:
        json.dumps(arm_by_name("full").to_dict())


@tier(TIER_ORACLE)
class TestAggregation(unittest.TestCase):
    """Per-arm summaries must expose the seed spread, not hide it behind a mean."""

    @staticmethod
    def _campaign(arm: str, seed: int, edges: int, signatures: tuple[str, ...] = ()) -> CampaignResult:
        stats = parse_fuzzer_stats(
            f"execs_done : {edges * 10}\nedges_found : {edges}\nbitmap_cvg : 1.0%\nrun_time : 60\n",
            arm=arm,
            seed=seed,
        )
        crashes = [
            CrashRecord(arm, seed, Path(f"c{i}"), sig, "kind", "frame", 10)
            for i, sig in enumerate(signatures)
        ]
        return CampaignResult(arm=arm, seed=seed, stats=stats, crashes=crashes)

    def test_summary_reports_mean_and_bounds(self) -> None:
        arm = arm_by_name("full")
        summary = summarise_arm(
            arm,
            [
                self._campaign("full", 1, 100),
                self._campaign("full", 2, 140),
                self._campaign("full", 3, 120),
            ],
        )
        self.assertEqual(summary.execs_min, 1000)
        self.assertEqual(summary.edges_max, 140)
        self.assertAlmostEqual(summary.edges_mean, 120.0)
        self.assertEqual(summary.edges_spread, 40)

    def test_distinct_defects_are_union_across_seeds(self) -> None:
        arm = arm_by_name("full")
        summary = summarise_arm(
            arm,
            [
                self._campaign("full", 1, 100, ("sha256:a", "sha256:b")),
                self._campaign("full", 2, 110, ("sha256:b", "sha256:c")),
            ],
        )
        self.assertEqual(summary.crashes_total, 4, "every crash file is counted once")
        self.assertEqual(summary.unique_crashes, 3, "a shared signature is one defect")
        self.assertEqual(summary.unique_signatures, ("sha256:a", "sha256:b", "sha256:c"))

    def test_summarising_an_empty_arm_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            summarise_arm(arm_by_name("full"), [])

    def test_experiment_groups_campaigns_by_arm(self) -> None:
        experiment = Experiment(
            name="t", target="cjson", budget_kind="seconds", budget_limit=60, seeds=(1, 2)
        )
        experiment.add(self._campaign("stock", 1, 100))
        experiment.add(self._campaign("full", 1, 120))
        grouped = experiment.by_arm()
        self.assertEqual(set(grouped), {"stock", "full"})
        self.assertEqual(len(grouped["stock"]), 1)

    def test_experiment_is_json_serialisable(self) -> None:
        experiment = Experiment(
            name="t", target="cjson", budget_kind="seconds", budget_limit=60, seeds=(1,)
        )
        experiment.add(self._campaign("stock", 1, 100))
        json.dumps(experiment.to_dict())


@tier(TIER_CONSISTENCY)
class TestReportRendering(unittest.TestCase):
    """The human report must show the same numbers as the JSON, and state the spread."""

    def _summaries(self):
        return [
            summarise_arm(
                arm_by_name("stock"),
                [
                    CampaignResult(
                        "stock", 1, parse_fuzzer_stats("edges_found : 100\n", arm="stock", seed=1)
                    ),
                ],
            ),
            summarise_arm(
                arm_by_name("full"),
                [
                    CampaignResult(
                        "full", 1, parse_fuzzer_stats("edges_found : 130\n", arm="full", seed=1)
                    ),
                ],
            ),
        ]

    def test_table_lists_every_arm(self) -> None:
        table = render_arm_table(self._summaries())
        self.assertIn("stock", table)
        self.assertIn("full", table)

    def test_comparison_marks_a_delta_as_inside_the_spread_when_it_is(self) -> None:
        # The single most important line in the report: a difference smaller than the noise
        # must be labelled as such rather than presented as a win.
        summaries = [
            summarise_arm(
                arm_by_name("stock"),
                [
                    CampaignResult(
                        "stock", 1, parse_fuzzer_stats("edges_found : 100\n", arm="stock", seed=1)
                    ),
                    CampaignResult(
                        "stock", 2, parse_fuzzer_stats("edges_found : 160\n", arm="stock", seed=2)
                    ),
                ],
            ),
            summarise_arm(
                arm_by_name("full"),
                [
                    CampaignResult(
                        "full", 1, parse_fuzzer_stats("edges_found : 135\n", arm="full", seed=1)
                    ),
                ],
            ),
        ]
        text = render_comparison(summaries, baseline="stock")
        self.assertIn("inside seed spread", text)

    def test_comparison_marks_a_delta_outside_the_spread_when_it_is(self) -> None:
        summaries = [
            summarise_arm(
                arm_by_name("stock"),
                [
                    CampaignResult(
                        "stock", 1, parse_fuzzer_stats("edges_found : 100\n", arm="stock", seed=1)
                    ),
                ],
            ),
            summarise_arm(
                arm_by_name("full"),
                [
                    CampaignResult(
                        "full", 1, parse_fuzzer_stats("edges_found : 200\n", arm="full", seed=1)
                    ),
                ],
            ),
        ]
        text = render_comparison(summaries, baseline="stock")
        self.assertIn("better (outside spread)", text)

    def test_missing_baseline_is_reported_not_invented(self) -> None:
        text = render_comparison(self._summaries(), baseline="absent")
        self.assertIn("did not run", text)

    def test_mechanism_table_shows_the_admission_ratio(self) -> None:
        # A policy that moved a number without changing the admission pattern moved it by
        # accident; the report has to be able to show that.
        text = render_mechanism(
            [
                {
                    "arm": "full",
                    "decisions": 100,
                    "admitted": 30,
                    "skipped": 70,
                    "admit_ratio": 0.3,
                    "score_mean": 0.45,
                }
            ]
        )
        self.assertIn("0.300", text)

    def test_no_mechanism_data_does_not_crash(self) -> None:
        self.assertIn("no plugin", render_mechanism([]))

    def test_writer_emits_both_forms_with_the_same_numbers(self) -> None:
        experiment = Experiment(
            name="unit", target="cjson", budget_kind="seconds", budget_limit=60, seeds=(1,)
        )
        experiment.add(
            CampaignResult("stock", 1, parse_fuzzer_stats("edges_found : 100\n", arm="stock", seed=1))
        )
        summaries = [summarise_arm(arm_by_name("stock"), experiment.results)]
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = write_results(
                experiment, summaries, [], out_dir=Path(tmp), baseline="stock"
            )
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            text = md_path.read_text(encoding="utf-8")
            self.assertEqual(payload["summaries"][0]["edges_mean"], 100.0)
            self.assertIn("100", text)
            self.assertEqual(payload["baseline"], "stock")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
