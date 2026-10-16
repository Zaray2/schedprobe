"""Tests for the shareable derivative export.

The export exists so that an evidence log can leave the room. That makes its failure mode
unusually expensive: a derivative that looks clean and is not would be handed to a third
party as if it were safe. So the tests here do not check that redaction *ran* - they check
that the sensitive strings are actually gone from the file, by reading the file.

Three properties are load-bearing:

* **the canaries are gone** - the same grep-everything approach as
  ``test_evidence_integrity``, but on the derivative;
* **the pseudonyms are not reversible by the reader** - the shipped ``--redact`` keys its
  pseudonyms with the run id, and the run id is *inside the log*, so a /24 falls to 256
  guesses. The export keys with an unpublished salt, and this is tested by brute force
  rather than asserted in a comment;
* **the derivative says what it is** - non-replayable, derived from a named digest, and
  the chain attests to the redacted content only. A derivative presented as the original
  would be worse than no derivative at all.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from schedprobe.errors import EvidenceError
from schedprobe.evidence import file_digest, read_records, verify_chain
from schedprobe.export import EXPORT_SUFFIX, export_run, redact_structure

ROOT = Path(__file__).resolve().parents[1]

TARGET = "10.77.88.9"
LABEL = "LABEL-CANARY-6f2a"
NOTES = "NOTES-CANARY-9c41"
AUTH = "AUTH-CANARY-4d17"
CANARIES = (TARGET, "10.77.88.0", LABEL, NOTES, AUTH)


class TestStructureRules(unittest.TestCase):
    """The walker, exercised directly so the rules are visible without a run."""

    def test_host_key_is_pseudonymised_even_for_a_hostname(self) -> None:
        # Pattern-matching alone would leave a hostname target in the clear, so the rule
        # is keyed on the field name as well.
        payload = {"host": "scanner.internal.example.invalid", "port": 80}
        out, hits, _ = redact_structure(payload, salt="s")
        self.assertTrue(out["host"].startswith("h:"))
        self.assertEqual(out["port"], 80)
        self.assertEqual(hits, 1)

    def test_addresses_inside_free_text_are_rewritten(self) -> None:
        payload = {"detail": "connected to 10.0.0.5:443 after 12ms"}
        out, _, _ = redact_structure(payload, salt="s")
        self.assertNotIn("10.0.0.5", out["detail"])
        self.assertIn(":443", out["detail"])

    def test_cidr_keeps_the_prefix_length(self) -> None:
        payload = {"segment": "10.0.5.0/24"}
        out, _, _ = redact_structure(payload, salt="s")
        self.assertTrue(out["segment"].endswith("/24"))
        self.assertNotIn("10.0.5.0", out["segment"])

    def test_pair_keys_are_rewritten(self) -> None:
        payload = {"reservations": {"10.0.0.7:8080": 600}}
        out, _, _ = redact_structure(payload, salt="s")
        key = next(iter(out["reservations"]))
        self.assertNotIn("10.0.0.7", key)
        self.assertTrue(key.endswith(":8080"))

    def test_pseudonyms_are_stable_for_one_salt_and_differ_across_salts(self) -> None:
        payload = {"host": TARGET}
        first, _, _ = redact_structure(payload, salt="a")
        again, _, _ = redact_structure(payload, salt="a")
        other, _, _ = redact_structure(payload, salt="b")
        self.assertEqual(first["host"], again["host"])
        self.assertNotEqual(first["host"], other["host"])

    def test_free_text_fields_are_dropped_by_default(self) -> None:
        payload = {"notes": NOTES, "label": LABEL, "authorization": AUTH}
        out, _, dropped = redact_structure(payload, salt="s")
        self.assertEqual(dropped, 3)
        for key in ("notes", "label", "authorization"):
            self.assertNotIn("CANARY", out[key])
            self.assertIn("redacted", out[key])
            # Length is kept: it is useful for a reader to see that something was there.
            self.assertIn(str(len(payload[key])), out[key])

    def test_keep_notes_preserves_them(self) -> None:
        payload = {"notes": NOTES}
        out, _, dropped = redact_structure(payload, salt="s", keep_notes=True)
        self.assertEqual(out["notes"], NOTES)
        self.assertEqual(dropped, 0)

    def test_run_label_suffix_is_caught(self) -> None:
        # The config calls it ``run_label``, not ``label``; an exact-name match missed it
        # and let the canary through.
        payload = {"run_label": LABEL}
        out, _, dropped = redact_structure(payload, salt="s")
        self.assertEqual(dropped, 1)
        self.assertNotIn(LABEL, out["run_label"])

    def test_argv_values_after_free_text_flags_are_redacted(self) -> None:
        # A log written by an older version still has the verbatim argv in it, so the
        # exporter re-applies the rule instead of trusting the writer.
        payload = {
            "argv": ["scan", "--notes", NOTES, "--label", LABEL, "--authorization=EQ", "--budget", "5000"]
        }
        out, _, dropped = redact_structure(payload, salt="s")
        argv = out["argv"]
        self.assertNotIn(NOTES, argv)
        self.assertNotIn(LABEL, argv)
        self.assertIn("--notes", argv, "flag names stay, so the invocation is still auditable")
        self.assertIn("--budget", argv)
        self.assertIn("5000", argv)
        self.assertIn("--authorization=<redacted>", argv)
        self.assertGreaterEqual(dropped, 3)

    def test_walks_nested_structures(self) -> None:
        payload = {"a": [{"host": TARGET}, {"b": {"detail": TARGET}}]}
        out, hits, _ = redact_structure(payload, salt="s")
        blob = json.dumps(out)
        self.assertNotIn(TARGET, blob)
        self.assertGreaterEqual(hits, 2)

    def test_non_strings_pass_through(self) -> None:
        payload = {"count": 3, "ok": True, "nothing": None, "rate": 0.5}
        out, hits, _ = redact_structure(payload, salt="s")
        self.assertEqual(out, payload)
        self.assertEqual(hits, 0)


class TestExportRun(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="schedprobe-export-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "schedprobe",
                "scan",
                "-t",
                TARGET,
                "-p",
                "80,443",
                "--backend",
                "fake",
                "--scenario",
                "healthy",
                "--budget",
                "5000",
                "--out-dir",
                str(self.tmp),
                "--redact",
                "--label",
                LABEL,
                "--notes",
                NOTES,
                "--authorization",
                AUTH,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.run_dir = next(p for p in self.tmp.iterdir() if p.is_dir())
        self.source = self.run_dir / "evidence.jsonl"

    def _export(self, **kwargs) -> tuple[Path, object]:
        out = self.run_dir / "shared.redacted.jsonl"
        report = export_run(self.source, out, **kwargs)
        return out, report

    def test_every_canary_is_gone_from_the_derivative(self) -> None:
        out, _ = self._export()
        text = out.read_text(encoding="utf-8")
        for needle in CANARIES:
            self.assertNotIn(needle, text, f"{needle} survived into the derivative")

    def test_the_original_still_has_them(self) -> None:
        # Control: proves the canaries really were in the source, so the test above is
        # testing redaction rather than testing an empty run.
        source = self.source.read_text(encoding="utf-8")
        self.assertIn(TARGET, source)
        self.assertIn(NOTES, source)

    def test_hosts_are_pseudonymised_consistently(self) -> None:
        out, _ = self._export()
        records = list(read_records(out))
        header = next(r for r in records if r.kind == "source-run-header")
        pseudonym = header.data["data"]["targets"][0]
        self.assertTrue(pseudonym.startswith("h:"))
        # The same host must map to the same pseudonym everywhere, or a reader sees two
        # different identifiers for one machine.
        text = out.read_text(encoding="utf-8")
        self.assertEqual(text.count(TARGET), 0)
        self.assertIn(pseudonym, text)

    def test_the_derivative_declares_itself(self) -> None:
        out, report = self._export()
        header = next(r for r in read_records(out) if r.kind == "run-header")
        data = header.data
        self.assertTrue(data["derivative"])
        self.assertFalse(data["replayable"])
        self.assertTrue(data["replay_note"])
        self.assertIn("redaction", data)
        self.assertFalse(data["redaction"]["salt_published"])
        self.assertEqual(data["redaction"]["salt_commitment"], report.salt_commitment)

    def test_derivative_of_names_the_source_digest(self) -> None:
        out, report = self._export()
        header = next(r for r in read_records(out) if r.kind == "run-header")
        digest, _ = file_digest(self.source)
        self.assertEqual(header.data["derivative_of"], digest)
        self.assertEqual(report.source_digest, digest)

    def test_the_derivatives_own_chain_verifies(self) -> None:
        out, _ = self._export()
        self.assertTrue(verify_chain(out).ok)

    def test_the_derivative_is_not_replayable_and_says_so(self) -> None:
        # Replay must refuse it. A silent success here would be worse than a failure: it
        # would suggest the redacted log reproduces the original schedule, which it cannot,
        # because the /24 that segmentation depends on is gone.
        out, _ = self._export()
        result = subprocess.run(
            [sys.executable, "-m", "schedprobe", "replay", str(out), "--strict"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, "replay must not claim success on a derivative")

    def test_reproducible_with_an_explicit_salt(self) -> None:
        one, report_one = self._export(salt="deadbeef")
        first = one.read_text(encoding="utf-8")
        one.unlink()
        two, report_two = self._export(salt="deadbeef")
        second = two.read_text(encoding="utf-8")
        self.assertEqual(report_one.salt_commitment, report_two.salt_commitment)

        # ``exported_at`` is the one field that is expected to differ, because it records
        # when the export ran rather than what it contains. Everything else - including the
        # pseudonyms - must be identical for a given salt.
        def bodies(text: str) -> list[str]:
            out = []
            for line in text.splitlines():
                data = json.loads(line)["data"]
                if isinstance(data, dict):
                    data.pop("exported_at", None)
                out.append(json.dumps(data, sort_keys=True))
            return out

        pairs = list(zip(bodies(first), bodies(second), strict=True))
        self.assertEqual([left for left, _ in pairs], [right for _, right in pairs])

    def test_random_salt_by_default_is_not_in_the_file(self) -> None:
        out, report = self._export()
        self.assertNotIn(report.salt, out.read_text(encoding="utf-8"))
        self.assertEqual(
            report.salt_commitment, "sha256:" + hashlib.sha256(report.salt.encode()).hexdigest()
        )

    def test_pseudonyms_resist_a_brute_force_over_the_owning_slash_24(self) -> None:
        """The property that makes this worth having over ``--redact``.

        ``--redact`` keys pseudonyms with the run id, and the run id sits inside the log,
        so a reader can enumerate 256 candidates and match one. The export keys with a salt
        that is not written down, so the same enumeration must fail - and if the salt ever
        became the run id again, this test would catch it.
        """
        out, report = self._export()
        header = next(r for r in read_records(out) if r.kind == "run-header")
        run_id = header.data["derivative_of_run_id"]
        pseudonym = next(r for r in read_records(out) if r.kind == "source-run-header").data["data"][
            "targets"
        ][0]

        def pseudonym_for(host: str, salt: str) -> str:
            digest = hmac.new(salt.encode("utf-8"), f"{host}:0".encode(), hashlib.sha256)
            return f"h:{digest.hexdigest()[:12]}"

        # Wrong key: the run id, which is what the console redaction uses.
        recovered_with_run_id = [
            f"10.77.88.{last}"
            for last in range(256)
            if pseudonym_for(f"10.77.88.{last}", run_id) == pseudonym
        ]
        self.assertEqual(
            recovered_with_run_id, [], "the run id recovered the address: the salt is not secret"
        )
        # Right key: proves the enumeration itself works, so the empty result above is not
        # an artefact of a broken loop.
        recovered_with_salt = [
            f"10.77.88.{last}"
            for last in range(256)
            if pseudonym_for(f"10.77.88.{last}", report.salt) == pseudonym
        ]
        self.assertEqual(recovered_with_salt, [TARGET])

    def test_refuses_to_overwrite_an_existing_derivative(self) -> None:
        self._export()
        with self.assertRaises(EvidenceError) as ctx:
            self._export()
        self.assertIn("overwrite", str(ctx.exception))

    def test_refuses_to_export_a_broken_log(self) -> None:
        # Exporting a log that does not verify would launder a broken record into a
        # clean-looking derivative, which is the one outcome worse than refusing.
        lines = self.source.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[2])
        payload["data"]["tampered"] = True
        lines[2] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.source.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(verify_chain(self.source).ok, "the tamper must break the chain")
        with self.assertRaises(EvidenceError) as ctx:
            export_run(self.source, self.run_dir / "nope.jsonl")
        self.assertIn("does not verify", str(ctx.exception))

    def test_missing_source_is_reported(self) -> None:
        with self.assertRaises(EvidenceError):
            export_run(self.run_dir / "absent.jsonl", self.run_dir / "x.jsonl")

    def test_report_serialises(self) -> None:
        _, report = self._export()
        payload = report.to_dict()
        self.assertFalse(payload["replayable"])
        self.assertFalse(payload["salt_published"])
        self.assertTrue(payload["limitations"])
        json.dumps(payload)  # must be JSON-serialisable for --json

    def test_default_output_name_follows_the_suffix(self) -> None:
        self.assertTrue(EXPORT_SUFFIX.startswith("."))
        out, report = self._export()
        self.assertTrue(out.name.endswith(EXPORT_SUFFIX))
        self.assertTrue(report.manifest_path.is_file())
        self.assertNotEqual(report.manifest_path.name, "manifest.json")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
