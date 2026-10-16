"""Tests for run-to-run comparison, reporting, and the CLI contract.

Two themes:

* **diff must not cry wolf.** A bigger budget reaches more ports, and those ports must be
  reported as a coverage difference rather than as newly opened services.
* **the CLI must fail loudly and specifically.** Exit codes are part of the interface
  (scripts depend on them), so each one has a test, including the negative cases.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from schedprobe.cli.console import (
    EXIT_EVIDENCE,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_REPLAY,
    EXIT_USAGE,
    Emitter,
    configure_stdio,
    exit_code_for,
    run_async,
)
from schedprobe.cli.main import main
from schedprobe.diff import DiffReport, PortDelta, diff_states, filter_deltas, severity_rank
from schedprobe.errors import (
    BackendError,
    BudgetError,
    ConfigError,
    EvidenceError,
    PolicyError,
    SchedProbeError,
    TargetValidationError,
)
from schedprobe.models import PortState, ProbeResult, Verdict
from schedprobe.reporting import (
    render_benchmark_table,
    render_diff,
    render_replay,
    render_run_table,
    render_summary,
    render_table,
    render_verify,
    sanitize,
    write_results,
)


def _delta(kind: str, severity: str = "info") -> PortDelta:
    return PortDelta("10.0.0.1", 80, kind, severity, "closed", "open", "test")


class TestDiffClassification(unittest.TestCase):
    def test_identical_runs_produce_no_deltas(self) -> None:
        states = {("10.0.0.1", 80): PortState.OPEN}
        report = diff_states(states, states)
        self.assertEqual(report.deltas, [])
        self.assertTrue(report.to_dict()["counts"]["new"] == 0)

    def _history(self, state: PortState, times: int = 3) -> dict:
        return {("10.0.0.1", 80): [state] * times}

    def test_confirmed_change_is_reported_as_changed(self) -> None:
        left = {("10.0.0.1", 80): PortState.CLOSED}
        right = {("10.0.0.1", 80): PortState.OPEN}
        report = diff_states(
            left,
            right,
            left_history=self._history(PortState.CLOSED),
            right_history=self._history(PortState.OPEN),
        )
        self.assertEqual(len(report.changed), 1)
        self.assertEqual(report.changed[0].severity, "high")
        self.assertEqual(report.changed[0].before, "closed")
        self.assertEqual(report.changed[0].after, "open")

    def test_unconfirmed_change_is_unstable_not_changed(self) -> None:
        left = {("10.0.0.1", 80): PortState.CLOSED}
        right = {("10.0.0.1", 80): PortState.OPEN}
        report = diff_states(left, right)  # no histories -> no confirmation
        self.assertEqual(report.changed, [])
        self.assertEqual(len(report.unstable), 1)
        self.assertEqual(report.unstable[0].severity, "info")

    def test_undetermined_on_one_side_is_unstable(self) -> None:
        left = {("10.0.0.1", 80): PortState.UNDETERMINED}
        right = {("10.0.0.1", 80): PortState.FILTERED}
        report = diff_states(left, right)
        self.assertEqual(len(report.unstable), 1)

    def test_genuine_new_port_with_agreement_is_changed_or_new(self) -> None:
        left = {("10.0.0.1", 80): PortState.CLOSED}
        right = {("10.0.0.1", 80): PortState.OPEN}
        report = diff_states(
            left,
            right,
            left_history=self._history(PortState.CLOSED, 2),
            right_history=self._history(PortState.OPEN, 2),
        )
        self.assertEqual(len(report.changed), 1)

    def test_out_of_scope_pairs_are_not_probed_not_new(self) -> None:
        left = {("10.0.0.1", 80): PortState.CLOSED}
        right = {("10.0.0.1", 80): PortState.CLOSED, ("10.0.0.1", 443): PortState.OPEN}
        report = diff_states(
            left,
            right,
            left_history=self._history(PortState.CLOSED, 2),
            right_history={("10.0.0.1", 443): [PortState.OPEN] * 2},
            scope={("10.0.0.1", 80)},
        )
        self.assertEqual(report.new, [])
        self.assertEqual(len(report.not_probed), 1)
        self.assertEqual(report.not_probed[0].after, "open")

    def test_in_scope_new_port_is_reported_as_new(self) -> None:
        left = {("10.0.0.1", 80): PortState.CLOSED}
        right = {("10.0.0.1", 80): PortState.CLOSED, ("10.0.0.1", 443): PortState.OPEN}
        report = diff_states(
            left,
            right,
            scope={("10.0.0.1", 80), ("10.0.0.1", 443)},
        )
        self.assertEqual(len(report.new), 1)
        self.assertEqual(report.new[0].kind, "new")

    def test_disappeared_open_port_is_medium_severity(self) -> None:
        left = {("10.0.0.1", 80): PortState.OPEN}
        right = {}
        report = diff_states(left, right, scope={("10.0.0.1", 80)})
        self.assertEqual(report.disappeared[0].severity, "medium")

    def test_report_dict_shape(self) -> None:
        payload = diff_states(
            {("10.0.0.1", 80): PortState.OPEN}, {("10.0.0.1", 80): PortState.OPEN}
        ).to_dict()
        for key in (
            "left",
            "right",
            "rules_version",
            "counts",
            "new",
            "disappeared",
            "changed",
            "unstable",
            "not_probed",
        ):
            self.assertIn(key, payload)

    def test_severity_ranking_and_filtering(self) -> None:
        self.assertLess(severity_rank("high"), severity_rank("info"))
        deltas = [_delta("changed", "high"), _delta("new", "medium"), _delta("unstable", "info")]
        self.assertEqual(len(filter_deltas(deltas, min_severity="high")), 1)
        self.assertEqual(len(filter_deltas(deltas, min_severity="medium")), 2)
        self.assertEqual(len(filter_deltas(deltas, kinds=["unstable"])), 1)
        self.assertEqual(len(filter_deltas(deltas)), 3)

    def test_report_accessors_match_kinds(self) -> None:
        report = DiffReport(left="a", right="b")
        report.deltas.append(PortDelta("h", 1, "changed", "high", "closed", "open"))
        self.assertEqual(report.changed[0].kind, "changed")
        self.assertEqual(report.not_probed, [])


class TestSanitize(unittest.TestCase):
    def test_strips_control_and_escape_characters(self) -> None:
        self.assertNotIn("\x1b", sanitize("a\x1b[31mred\x1b[0m"))
        self.assertNotIn("\r", sanitize("a\rb"))
        self.assertNotIn("\n", sanitize("a\nb"))

    def test_strips_line_and_paragraph_separators(self) -> None:
        self.assertNotIn("\u2028", sanitize("a\u2028b"))
        self.assertNotIn("\u2029", sanitize("a\u2029b"))

    def test_keeps_printable_unicode(self) -> None:
        self.assertEqual(sanitize("扫描完成"), "扫描完成")

    def test_truncates_with_marker(self) -> None:
        out = sanitize("x" * 100, limit=10)
        self.assertEqual(len(out), 10)
        self.assertTrue(out.endswith("..."))

    def test_handles_non_string_input(self) -> None:
        self.assertEqual(sanitize(12345), "12345")
        self.assertEqual(sanitize(None), "None")


class TestRenderers(unittest.TestCase):
    def test_render_table_has_one_rule_and_no_ansi(self) -> None:
        table = render_table(["a", "b"], [[1, 2], [3, 4]])
        lines = table.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertNotIn("\x1b", table)
        self.assertTrue(set(lines[1]) <= {"-", "+"}, lines[1])
        self.assertTrue(lines[1].startswith("-"))

    def test_render_table_handles_no_headers(self) -> None:
        self.assertEqual(render_table([], []), "")

    def test_render_summary_formats_ratios_and_times(self) -> None:
        text = render_summary(
            {"waste_ratio": 0.5, "elapsed_s": 1.25, "time_to_first_open_s": None, "first_open": ("h", 80)}
        )
        self.assertIn("50.0%", text)
        self.assertIn("1.2500s", text)
        self.assertIn("h:80", text)

    def test_render_run_table_hides_closed_by_default(self) -> None:
        results = {
            ("h", 80): ProbeResult("h", 80, PortState.OPEN, Verdict.CONNECTED, 1, 0.99),
            ("h", 81): ProbeResult("h", 81, PortState.CLOSED, Verdict.REFUSED, 1, 0.95),
        }
        table = render_run_table(results)
        self.assertIn("80", table)
        self.assertNotIn("81", table)
        self.assertIn("closed ports omitted", table)

    def test_render_run_table_includes_closed_on_request(self) -> None:
        results = {("h", 81): ProbeResult("h", 81, PortState.CLOSED, Verdict.REFUSED, 1, 0.95)}
        self.assertIn("81", render_run_table(results, include_closed=True))

    def test_render_run_table_applies_the_display_callable(self) -> None:
        results = {
            ("10.0.0.1", 80): ProbeResult("10.0.0.1", 80, PortState.OPEN, Verdict.CONNECTED, 1, 0.99)
        }
        table = render_run_table(results, display_host=lambda host: "h:deadbeef")
        self.assertIn("h:deadbeef", table)
        self.assertNotIn("10.0.0.1", table)

    def test_render_run_table_reports_hidden_rows(self) -> None:
        results = {
            (f"h{i}", 80): ProbeResult(f"h{i}", 80, PortState.OPEN, Verdict.CONNECTED, 1, 0.99)
            for i in range(5)
        }
        self.assertIn("hidden", render_run_table(results, max_rows=2))

    def test_render_verify_ok_and_fail(self) -> None:
        ok = render_verify(
            {
                "ok": True,
                "records": 3,
                "run_id": "r",
                "head": "sha256:x",
                "kinds": {"probe": 3},
                "path": "p",
            }
        )
        self.assertTrue(ok.startswith("OK"))
        bad = render_verify({"ok": False, "records": 0, "first_bad_seq": 2, "reason": "nope"})
        self.assertTrue(bad.startswith("FAIL"))
        self.assertIn("nope", bad)

    def test_render_replay_lists_divergences(self) -> None:
        text = render_replay(
            {
                "ok": False,
                "run_id": "r",
                "planner": "adaptive",
                "observations": 1,
                "decisions_checked": 1,
                "rank_updates_checked": 0,
                "live_changes_checked": 0,
                "frontier_match": True,
                "segments_match": False,
                "divergences": ["a", "b"],
            }
        )
        self.assertIn("FAIL", text)
        self.assertIn("- a", text)

    def test_render_diff_shows_counts(self) -> None:
        text = render_diff(
            {
                "left": "a",
                "right": "b",
                "new": ["x"],
                "disappeared": [],
                "changed": [],
                "unstable": [],
                "note": "n",
            }
        )
        self.assertIn("new         : 1", text)

    def test_render_benchmark_table(self) -> None:
        payload = {
            "scenario": "s",
            "seed": 1,
            "budget": 10,
            "hosts": 1,
            "ports": 2,
            "runs": [
                {
                    "planner": "adaptive",
                    "open_found": 1,
                    "open_total": 2,
                    "recall": 0.5,
                    "precision": 1.0,
                    "dispatched": 3,
                    "cost_spent": 100,
                    "cost_of_filtered": 50,
                    "waste_ratio": 0.5,
                    "time_to_first_open_cost": 10,
                }
            ],
            "delta_vs_fixed": {},
        }
        text = render_benchmark_table(payload)
        self.assertIn("adaptive", text)
        self.assertIn("50.0%", text)


class TestWriteResults(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.results = {
            ("h", 80): ProbeResult("h", 80, PortState.OPEN, Verdict.CONNECTED, 3, 0.99, detail="banner"),
            ("h", 81): ProbeResult("h", 81, PortState.CLOSED, Verdict.REFUSED, 1, 0.95),
        }

    def test_json(self) -> None:
        path = write_results(self.dir / "r.json", self.results, fmt="json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["count"], 2)

    def test_jsonl(self) -> None:
        path = write_results(self.dir / "r.jsonl", self.results, fmt="jsonl")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        json.loads(lines[0])

    def test_csv(self) -> None:
        path = write_results(self.dir / "r.csv", self.results, fmt="csv")
        text = path.read_text(encoding="utf-8")
        self.assertIn("host,port,state", text)
        self.assertEqual(len(text.strip().splitlines()), 3)

    def test_include_closed_and_max_results(self) -> None:
        path = write_results(
            self.dir / "r.json", self.results, fmt="json", include_closed=False, max_results=1
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["port"], 80)

    def test_display_host_hook_is_applied(self) -> None:
        path = write_results(
            self.dir / "r.json", self.results, fmt="json", display_host=lambda host: "redacted"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["results"][0]["host"], "redacted")

    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            write_results(self.dir / "r.xml", self.results, fmt="xml")


class TestEmitter(unittest.TestCase):
    def test_data_prints_json_in_both_modes(self) -> None:
        for json_mode in (False, True):
            buffer = io.StringIO()
            Emitter(json_mode=json_mode, stream=buffer).data({"a": 1})
            self.assertEqual(json.loads(buffer.getvalue()), {"a": 1})

    def test_say_is_silent_in_json_mode(self) -> None:
        buffer = io.StringIO()
        emitter = Emitter(json_mode=True, stream=buffer)
        emitter.say("hidden")
        emitter.say("forced", force=True)
        self.assertEqual(buffer.getvalue().strip(), "forced")

    def test_quiet_suppresses_say_but_not_force(self) -> None:
        buffer = io.StringIO()
        emitter = Emitter(quiet=True, stream=buffer)
        emitter.say("hidden")
        emitter.say("forced", force=True)
        self.assertEqual(buffer.getvalue().strip(), "forced")

    def test_configure_stdio_returns_an_encoding(self) -> None:
        self.assertIn(
            configure_stdio().lower(),
            {"utf-8", "utf8", "gbk", "cp936", "ascii", "utf-16", "utf-16-le", "utf-16-be"},
        )

    def test_run_async_returns_the_value(self) -> None:
        async def coro() -> int:
            return 7

        self.assertEqual(run_async(coro()), 7)


class TestExitCodes(unittest.TestCase):
    def test_mapping_is_specific(self) -> None:
        self.assertEqual(exit_code_for(EvidenceError("x")), EXIT_EVIDENCE)
        self.assertEqual(exit_code_for(ConfigError("x")), EXIT_USAGE)
        self.assertEqual(exit_code_for(TargetValidationError("x")), EXIT_USAGE)
        self.assertEqual(exit_code_for(BudgetError("x")), EXIT_USAGE)
        self.assertEqual(exit_code_for(PolicyError("x")), EXIT_USAGE)
        self.assertEqual(exit_code_for(BackendError("x")), EXIT_USAGE)
        self.assertEqual(exit_code_for(SchedProbeError("x")), EXIT_USAGE)
        self.assertEqual(exit_code_for(ValueError("x")), EXIT_INTERNAL)

    def test_codes_are_distinct(self) -> None:
        codes = {EXIT_OK, EXIT_INTERNAL, EXIT_USAGE, EXIT_EVIDENCE, EXIT_REPLAY}
        self.assertEqual(len(codes), 5)


class TestCliContract(unittest.TestCase):
    """Run the real ``main`` so the tests cover argparse wiring, not just helpers."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_version(self) -> None:
        self.assertEqual(main(["version"]), EXIT_OK)

    def test_no_subcommand_is_usage(self) -> None:
        self.assertEqual(main([]), EXIT_USAGE)

    def test_config_show(self) -> None:
        self.assertEqual(main(["config", "show"]), EXIT_OK)

    def test_config_init_then_validate(self) -> None:
        path = self.dir / "cfg.toml"
        self.assertEqual(main(["config", "init", str(path)]), EXIT_OK)
        self.assertTrue(path.is_file())
        self.assertEqual(main(["config", "validate", str(path)]), EXIT_OK)

    def test_config_init_refuses_to_clobber(self) -> None:
        path = self.dir / "cfg.toml"
        path.write_text("x", encoding="utf-8")
        self.assertEqual(main(["config", "init", str(path)]), EXIT_USAGE)
        self.assertEqual(main(["config", "init", str(path), "--force"]), EXIT_OK)

    def test_config_validate_missing_file(self) -> None:
        self.assertEqual(main(["config", "validate", str(self.dir / "nope.toml")]), EXIT_USAGE)

    def test_scan_writes_a_verifiable_run(self) -> None:
        code = main(
            [
                "scan",
                "-t",
                "127.0.0.1",
                "-p",
                "80,443",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.dir),
            ]
        )
        self.assertEqual(code, EXIT_OK)
        runs = list(self.dir.glob("*/evidence.jsonl"))
        self.assertEqual(len(runs), 1)
        self.assertEqual(main(["verify", str(runs[0].parent)]), EXIT_OK)
        self.assertEqual(main(["replay", str(runs[0]), "--strict"]), EXIT_OK)

    def test_scan_rejects_a_bad_planner(self) -> None:
        # ``--planner`` uses argparse choices, so a bad value is a parse error (exit 2).
        with self.assertRaises(SystemExit) as ctx:
            main(
                [
                    "scan",
                    "-t",
                    "127.0.0.1",
                    "-p",
                    "80",
                    "--backend",
                    "fake",
                    "--planner",
                    "nope",
                    "--out-dir",
                    str(self.dir),
                ]
            )
        self.assertEqual(ctx.exception.code, EXIT_USAGE)

    def test_scan_rejects_a_public_target_without_opt_in(self) -> None:
        code = main(["scan", "-t", "8.8.8.8", "-p", "80", "--backend", "fake", "--out-dir", str(self.dir)])
        self.assertEqual(code, EXIT_USAGE)

    def test_verify_on_a_missing_run(self) -> None:
        self.assertEqual(main(["verify", str(self.dir / "nope")]), EXIT_EVIDENCE)

    def test_verify_on_a_tampered_chain(self) -> None:
        main(
            [
                "scan",
                "-t",
                "127.0.0.1",
                "-p",
                "80",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.dir),
            ]
        )
        evidence = next(self.dir.glob("*/evidence.jsonl"))
        lines = evidence.read_text(encoding="utf-8").splitlines()
        lines[2] = lines[2].replace('"plan"', '"tampered"', 1)
        evidence.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(main(["verify", str(evidence)]), EXIT_EVIDENCE)

    def test_explain_runs_against_a_real_log(self) -> None:
        main(
            [
                "scan",
                "-t",
                "127.0.0.1",
                "-p",
                "80",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.dir),
            ]
        )
        evidence = next(self.dir.glob("*/evidence.jsonl"))
        self.assertEqual(main(["explain", str(evidence), "--top", "1"]), EXIT_OK)
        self.assertEqual(main(["explain", str(evidence), "--reasons"]), EXIT_OK)

    def test_explain_rejects_a_malformed_pair(self) -> None:
        main(
            [
                "scan",
                "-t",
                "127.0.0.1",
                "-p",
                "80",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.dir),
            ]
        )
        evidence = next(self.dir.glob("*/evidence.jsonl"))
        self.assertEqual(main(["explain", str(evidence), "--pair", "nonsense"]), EXIT_USAGE)

    def test_diff_of_a_run_with_itself_is_empty(self) -> None:
        main(
            [
                "scan",
                "-t",
                "127.0.0.1",
                "-p",
                "80,443",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.dir),
            ]
        )
        run_dir = next(self.dir.glob("*/evidence.jsonl")).parent
        self.assertEqual(main(["diff", str(run_dir), str(run_dir)]), EXIT_OK)

    def test_bench_smoke(self) -> None:
        self.assertEqual(
            main(["bench", "--scenario", "healthy", "--budget", "5000", "--out-dir", str(self.dir)]),
            EXIT_OK,
        )

    def test_bench_honours_the_save_path(self) -> None:
        target = self.dir / "custom-name.json"
        self.assertEqual(
            main(
                [
                    "bench",
                    "--scenario",
                    "healthy",
                    "--budget",
                    "5000",
                    "--out-dir",
                    str(self.dir),
                    "--save",
                    str(target),
                ]
            ),
            EXIT_OK,
        )
        self.assertTrue(target.is_file())

    def test_demo_smoke(self) -> None:
        self.assertEqual(
            main(["demo", "--scenario", "healthy", "--budget", "5000", "--out-dir", str(self.dir)]),
            EXIT_OK,
        )

    def test_redacted_scan_hides_the_host_in_artifacts(self) -> None:
        main(
            [
                "scan",
                "-t",
                "10.1.2.3",
                "-p",
                "80",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.dir),
                "--redact",
                "--format",
                "json",
            ]
        )
        results = next(self.dir.glob("*/results.json"))
        payload = json.loads(results.read_text(encoding="utf-8"))
        self.assertTrue(payload["results"], "the scan must have produced rows")
        for row in payload["results"]:
            self.assertNotEqual(row["host"], "10.1.2.3")
            self.assertTrue(row["host"].startswith("h:"), row["host"])

    def test_version_exits_through_argparse(self) -> None:
        # ``action="version"`` prints and raises SystemExit by design, so the contract is
        # "exit code 0", not "return value 0".
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
