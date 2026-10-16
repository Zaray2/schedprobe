"""Regression: ``--json`` must put exactly one parseable JSON document on stdout.

The Emitter documents the contract - "``json_mode`` suppresses human text entirely so
stdout stays machine-parseable" - and several subcommands quietly violated it by passing
``force=True`` to ``say``, which defeats json mode by design. A caller doing
``schedprobe verify --json | jq`` got a human table followed by JSON.

This is a contract test over the real CLI rather than over the Emitter, because the bug
was in the call sites: every subcommand has to be checked, and the list of subcommands is
exactly the thing that grows.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .tiers import TIER_CONTRACT, tier

ROOT = Path(__file__).resolve().parents[1]


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "schedprobe", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


@tier(TIER_CONTRACT)
class TestJsonModeContract(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="schedprobe-json-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        result = _cli(
            "scan",
            "-t",
            "10.0.0.1",
            "-p",
            "80,443",
            "--backend",
            "fake",
            "--scenario",
            "healthy",
            "--budget",
            "4000",
            "--out-dir",
            str(self.tmp),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.run_dir = next(p for p in self.tmp.iterdir() if p.is_dir())
        self.evidence = self.run_dir / "evidence.jsonl"

    def _assert_single_json_document(self, *args: str) -> dict:
        result = _cli(*args)
        self.assertEqual(result.returncode, 0, f"{args} failed: {result.stderr[-400:]}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:  # pragma: no cover - only on regression
            self.fail(
                f"{' '.join(args)} did not produce a single JSON document: {exc}\n"
                f"stdout was:\n{result.stdout[:500]}"
            )
        self.assertIsInstance(payload, dict)
        return payload

    def test_version(self) -> None:
        payload = self._assert_single_json_document("--json", "version")
        self.assertEqual(payload["tool"], "schedprobe")

    def test_config_show(self) -> None:
        payload = self._assert_single_json_document("--json", "config", "show")
        self.assertIn("planner", payload)

    def test_verify(self) -> None:
        payload = self._assert_single_json_document("--json", "verify", str(self.run_dir))
        self.assertTrue(payload["ok"])

    def test_replay(self) -> None:
        payload = self._assert_single_json_document("--json", "replay", str(self.evidence))
        self.assertIn("ok", payload)

    def test_explain(self) -> None:
        payload = self._assert_single_json_document("--json", "explain", str(self.evidence))
        self.assertIn("rows", payload)
        self.assertIn("total", payload)

    def test_explain_reasons(self) -> None:
        # ``--reasons`` printed bare JSON through ``say``, so it survived json mode only by
        # accident and would have vanished if ``force`` were ever corrected.
        payload = self._assert_single_json_document("--json", "explain", str(self.evidence), "--reasons")
        self.assertTrue(payload)

    def test_diff(self) -> None:
        payload = self._assert_single_json_document("--json", "diff", str(self.run_dir), str(self.run_dir))
        self.assertIn("counts", payload)

    def test_export(self) -> None:
        payload = self._assert_single_json_document("--json", "export", str(self.run_dir))
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["replayable"])
        self.assertFalse(payload["salt_published"])

    def test_bench(self) -> None:
        payload = self._assert_single_json_document(
            "--json",
            "bench",
            "--scenario",
            "healthy",
            "--budget",
            "4000",
            "--out-dir",
            str(self.tmp / "bench"),
        )
        self.assertIn("runs", payload)

    def test_the_flag_works_on_either_side_of_the_subcommand(self) -> None:
        # Regression: ``--json`` was declared twice. The subparser's default is False, so
        # ``--json verify <run>`` silently clobbered the global value and ran in text mode
        # while ``verify <run> --json`` worked - the same flag, two behaviours, depending
        # on where it was typed. ``default=argparse.SUPPRESS`` keeps them equivalent.
        before = _cli("--json", "verify", str(self.run_dir))
        after = _cli("verify", str(self.run_dir), "--json")
        self.assertEqual(before.returncode, 0, before.stderr[-300:])
        self.assertEqual(after.returncode, 0, after.stderr[-300:])
        self.assertEqual(json.loads(before.stdout), json.loads(after.stdout))

    def test_no_json_mode_still_prints_something_human(self) -> None:
        # The inverse contract: without --json, stdout must NOT be a bare JSON document,
        # otherwise the flag would be doing nothing.
        result = _cli("verify", str(self.run_dir))
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip())
        with self.assertRaises(json.JSONDecodeError):
            json.loads(result.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
