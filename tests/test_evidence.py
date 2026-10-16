"""Tests for the evidence log: hash chain, tamper detection, manifest, and redaction.

The chain is the project's core auditability claim, so the tamper tests are the point of
this module rather than an afterthought. They also document the *limit* of the claim:
truncation and full-chain rewriting are not detectable from the log alone - only the
manifest digest catches those, which is why the manifest exists.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from schedprobe.errors import EvidenceError
from schedprobe.evidence import (
    GENESIS_PREFIX,
    EvidenceLog,
    decision_timeline,
    file_digest,
    observation_timeline,
    read_records,
    reason_histogram,
    status_to_dict,
    verify_chain,
    write_manifest,
)
from schedprobe.util import canonical_json, redact, sha256_hex


def _write_chain(path: Path, count: int = 4) -> None:
    with EvidenceLog(path, "run-test", truncate=True) as log:
        for index in range(count):
            log.append("probe", {"index": index, "host": "10.0.0.1", "port": 80 + index})


class TestEvidenceLog(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "evidence.jsonl"

    def test_records_chain_from_genesis(self) -> None:
        _write_chain(self.path, 3)
        records = list(read_records(self.path))
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].prev, GENESIS_PREFIX + sha256_hex("run-test"))
        self.assertEqual(records[1].prev, records[0].hash)
        self.assertEqual(records[2].prev, records[1].hash)

    def test_sequence_numbers_are_contiguous(self) -> None:
        _write_chain(self.path, 5)
        self.assertEqual([r.seq for r in read_records(self.path)], [1, 2, 3, 4, 5])

    def test_reopening_an_existing_chain_continues_it(self) -> None:
        _write_chain(self.path, 2)
        with EvidenceLog(self.path, "run-test") as log:
            log.append("note", {"x": 1})
        records = list(read_records(self.path))
        self.assertEqual(len(records), 3)
        self.assertEqual(records[2].prev, records[1].hash)

    def test_refuses_to_append_to_another_runs_chain(self) -> None:
        _write_chain(self.path, 1)
        with self.assertRaises(EvidenceError):
            EvidenceLog(self.path, "other-run")

    def test_rejects_non_serializable_payload(self) -> None:
        with EvidenceLog(self.path, "run-test", truncate=True) as log:
            with self.assertRaises(EvidenceError):
                log.append("probe", {"bad": object()})

    def test_rejects_empty_kind(self) -> None:
        with EvidenceLog(self.path, "run-test", truncate=True) as log:
            with self.assertRaises(EvidenceError):
                log.append("", {"x": 1})

    def test_canonical_json_is_stable(self) -> None:
        self.assertEqual(canonical_json({"b": 1, "a": [2, 1]}), '{"a":[2,1],"b":1}')
        # key order in the input must not change the bytes that get hashed
        self.assertEqual(canonical_json({"a": 1, "b": 2}), canonical_json({"b": 2, "a": 1}))


class TestChainVerification(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "evidence.jsonl"
        _write_chain(self.path, 4)

    def _lines(self) -> list[str]:
        return [line for line in self.path.read_text(encoding="utf-8").splitlines() if line]

    def _write_lines(self, lines: list[str]) -> None:
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_intact_chain_verifies(self) -> None:
        status = verify_chain(self.path)
        self.assertTrue(status.ok, status.reason)
        self.assertEqual(status.records, 4)
        self.assertEqual(status.kinds, {"probe": 4})

    def test_edited_record_is_detected(self) -> None:
        lines = self._lines()
        payload = json.loads(lines[1])
        payload["data"]["port"] = 9999        # tamper with the body, keep the hash
        lines[1] = canonical_json(payload)
        self._write_lines(lines)
        status = verify_chain(self.path)
        self.assertFalse(status.ok)
        self.assertEqual(status.first_bad_seq, 2)
        self.assertIn("digest", status.reason)

    def test_deleted_record_is_detected(self) -> None:
        lines = self._lines()
        del lines[1]
        self._write_lines(lines)
        status = verify_chain(self.path)
        self.assertFalse(status.ok)
        self.assertEqual(status.first_bad_seq, 3)
        self.assertIn("discontinuity", status.reason)

    def test_swapped_records_are_detected(self) -> None:
        lines = self._lines()
        lines[1], lines[2] = lines[2], lines[1]
        self._write_lines(lines)
        self.assertFalse(verify_chain(self.path).ok)

    def test_genesis_replacement_is_detected(self) -> None:
        lines = self._lines()
        payload = json.loads(lines[0])
        payload["prev"] = GENESIS_PREFIX + sha256_hex("someone-else")
        lines[0] = canonical_json(payload)
        self._write_lines(lines)
        self.assertFalse(verify_chain(self.path).ok)

    def test_run_id_change_mid_chain_is_detected(self) -> None:
        lines = self._lines()
        payload = json.loads(lines[2])
        payload["run_id"] = "hijacked"
        payload["hash"] = "sha256:" + sha256_hex(canonical_json(
            {k: v for k, v in payload.items() if k != "hash"}
        ))
        lines[2] = canonical_json(payload)
        self._write_lines(lines)
        self.assertFalse(verify_chain(self.path).ok)

    def test_truncation_is_not_detectable_from_the_log_alone(self) -> None:
        """Documents the limit of the claim: a valid prefix still verifies.

        Detection of truncation is the manifest's job (the digest covers the whole file),
        which is why ``verify`` checks both and why the manifest must be stored or sent
        separately from the log.
        """
        lines = self._lines()
        self._write_lines(lines[:-2])
        status = verify_chain(self.path)
        self.assertTrue(status.ok, "a truncated chain is still a valid prefix")
        self.assertEqual(status.records, 2)

    def test_empty_log_fails_verification(self) -> None:
        self.path.write_text("", encoding="utf-8")
        status = verify_chain(self.path)
        self.assertFalse(status.ok)
        self.assertIn("empty", status.reason)

    def test_missing_file(self) -> None:
        with self.assertRaises(EvidenceError):
            verify_chain(self.path.parent / "nope.jsonl")

    def test_malformed_line_reports_a_line_number(self) -> None:
        self.path.write_text("{not json}\n", encoding="utf-8")
        with self.assertRaises(EvidenceError) as ctx:
            list(read_records(self.path))
        self.assertIn("line", str(ctx.exception))

    def test_missing_field_is_rejected(self) -> None:
        self.path.write_text('{"seq": 1, "kind": "probe"}\n', encoding="utf-8")
        with self.assertRaises(EvidenceError):
            list(read_records(self.path))

    def test_status_to_dict_is_json_serializable(self) -> None:
        payload = status_to_dict(self.path, verify_chain(self.path))
        json.dumps(payload)
        self.assertTrue(payload["ok"])


class TestManifest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "evidence.jsonl"
        _write_chain(self.path, 2)

    def test_digest_matches_file(self) -> None:
        digest, size = file_digest(self.path)
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(size, self.path.stat().st_size)

    def test_digest_changes_when_the_log_changes(self) -> None:
        before, _ = file_digest(self.path)
        with EvidenceLog(self.path, "run-test") as log:
            log.append("note", {"x": 1})
        after, _ = file_digest(self.path)
        self.assertNotEqual(before, after)

    def test_write_manifest_is_atomic_and_deterministic(self) -> None:
        target = write_manifest(self.dir, {"run_id": "r", "evidence_sha256": "sha256:x"})
        self.assertEqual(target.name, "manifest.json")
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(payload["run_id"], "r")
        self.assertIn("generated_at", payload)
        self.assertEqual([p.name for p in self.dir.glob("*.tmp*")], [])

    def test_manifest_records_are_stable_across_rewrites(self) -> None:
        write_manifest(self.dir, {"run_id": "r", "value": 1})
        write_manifest(self.dir, {"run_id": "r", "value": 2})
        payload = json.loads((self.dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["value"], 2)


class TestTimelines(unittest.TestCase):
    """The timelines are the data behind ``explain`` and ``diff``; they must be robust."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "evidence.jsonl"

    def _write_probe(self, log: EvidenceLog, host: str, port: int, state: str, reason: str) -> None:
        log.append(
            "probe",
            {
                "dispatched": {
                    "host": host, "port": port, "reason": reason, "timeout_s": 0.6,
                    "executed_timeout_s": 0.6, "attempt": 1, "is_confirmation": False,
                },
                "decision": {"host": host, "port": port + 1, "reason": "sweep-segment-first",
                             "timeout_s": 0.6, "priority": 0.3, "is_confirmation": False},
                "observation": {"host": host, "port": port, "state": state, "verdict": "timeout",
                                "cost_units": 600, "confidence": 0.45, "attempt": 1},
                "cost_spent": 600, "live_pairs": 10,
            },
        )

    def test_observation_timeline(self) -> None:
        with EvidenceLog(self.path, "r", truncate=True) as log:
            self._write_probe(log, "10.0.0.1", 80, "filtered", "sweep-segment-first")
        rows = observation_timeline(self.path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "10.0.0.1")
        self.assertEqual(rows[0]["port"], 80)
        self.assertEqual(rows[0]["state"], "filtered")
        self.assertEqual(rows[0]["cost"], 600)

    def test_decision_timeline_exposes_both_sides(self) -> None:
        with EvidenceLog(self.path, "r", truncate=True) as log:
            self._write_probe(log, "10.0.0.1", 80, "filtered", "confirm-inconclusive")
        rows = decision_timeline(self.path)
        self.assertEqual(rows[0]["scheduled_reason"], "confirm-inconclusive")
        self.assertEqual(rows[0]["next_host"], "10.0.0.1")
        self.assertEqual(rows[0]["next_port"], 81)

    def test_timeline_tolerates_missing_optional_fields(self) -> None:
        with EvidenceLog(self.path, "r", truncate=True) as log:
            log.append("probe", {"observation": {"host": "h", "port": 1, "state": "open"}})
        rows = decision_timeline(self.path)
        self.assertIsNone(rows[0]["cost"])
        self.assertIsNone(rows[0]["live_pairs"])

    def test_reason_histogram_accepts_rows_or_strings(self) -> None:
        with EvidenceLog(self.path, "r", truncate=True) as log:
            self._write_probe(log, "10.0.0.1", 80, "filtered", "sweep-segment-first")
            self._write_probe(log, "10.0.0.1", 81, "filtered", "confirm-inconclusive")
        rows = decision_timeline(self.path)
        self.assertEqual(
            reason_histogram(rows),
            {"confirm-inconclusive": 1, "sweep-segment-first": 1},
        )
        self.assertEqual(reason_histogram([{"reason": "x"}, {"reason": "x"}]), {"x": 2})
        self.assertEqual(reason_histogram([None, "y"]), {"unknown": 1, "y": 1})


class TestRedaction(unittest.TestCase):
    """``--redact`` must pseudonymise consistently within a run and scrubbable in logs."""

    def test_redact_removes_ipv4_literals(self) -> None:
        scrubbed = redact("scanning 10.1.2.3 now", salt="run1")
        self.assertNotIn("10.1.2.3", scrubbed)
        self.assertIn("h:", scrubbed)

    def test_redact_is_deterministic_for_a_salt(self) -> None:
        self.assertEqual(redact("10.1.2.3", salt="s"), redact("10.1.2.3", salt="s"))

    def test_redact_changes_with_the_salt(self) -> None:
        self.assertNotEqual(redact("10.1.2.3", salt="a"), redact("10.1.2.3", salt="b"))

    def test_redact_removes_credential_shaped_text(self) -> None:
        for text in (
            "api_key=abc123",
            "token: deadbeef",
            # Deliberately shaped like a real credential so the redactor is exercised.
            # These are synthetic, assembled at runtime so that secret scanners (and
            # reviewers skimming grep output) do not have to reason about whether a
            # literal in a test file is live.
            "Authorization: Bearer " + "eyJhbGciOi." + "payload." + "sig",
            "sk-" + "x" * 24,
            "ghp_" + "x" * 30,
            "AKIA" + "X" * 16,
        ):
            scrubbed = redact(text, salt="s")
            self.assertNotIn("abc123", scrubbed)
            self.assertNotIn("deadbeef", scrubbed)
            self.assertIn("<redacted>", scrubbed, text)
            self.assertNotEqual(scrubbed, text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
