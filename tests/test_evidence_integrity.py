"""P0: what the artifacts leak, and what tampering the chain can actually catch.

Two questions, both answered by execution rather than by reading the docstrings.

**Redaction coverage.** ``--redact`` is easy to *believe* and hard to *verify*, because
the sensitive strings travel through a dozen call sites before they reach a file. The
tests here plant a distinct canary in every user-controlled field (target, label, notes,
authorization reference) and then grep every artifact that was written. A canary that
survives into a file is a leak, and the expected-leak map below is the contract: it says
which artifact is allowed to keep what, and why.

**Tamper detection.** A hash chain over an append-only file catches *some* edits and not
others, and the difference matters when the tool is used as an audit record. The tests
spell out the boundary:

* a modified record, a removed middle record, a reordered pair and malformed JSON are all
  detected;
* a truncated tail is **not** detectable from the log alone - the remaining prefix is a
  perfectly valid chain. The manifest's ``evidence_sha256`` is what anchors it;
* rewriting the whole file is **not** detectable, because the chain is unkeyed SHA-256 and
  whoever can write the file can also recompute every hash. The chain is tamper
  *evidence*, not tamper *proof*, and no amount of internal consistency changes that.

If a test in the last group ever starts failing because someone added a keyed MAC, delete
it and update ``docs/architecture.md`` - do not quietly invert it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from schedprobe.evidence import (
    EvidenceLog,
    file_digest,
    read_records,
    verify_chain,
    write_manifest,
)
from schedprobe.util import canonical_json, redact, sha256_hex

from .tiers import TIER_ORACLE, tier

ROOT = Path(__file__).resolve().parents[1]

# Distinctive strings, each planted in exactly one user-controlled field, so a hit in an
# artifact can only have come from that field.
CANARY_TARGET = "10.77.88.9"
CANARY_LABEL = "LABEL-CANARY-6f2a"
CANARY_NOTES = "NOTES-CANARY-9c41"
CANARY_AUTH = "AUTH-CANARY-4d17"

CANARIES = {
    "target": CANARY_TARGET,
    "label": CANARY_LABEL,
    "notes": CANARY_NOTES,
    "auth": CANARY_AUTH,
}


def _run_scan(out_dir: Path, *extra: str) -> Path:
    """Run the CLI exactly as a user would, and return the single run directory."""
    cmd = [
        sys.executable,
        "-m",
        "schedprobe",
        "scan",
        "-t",
        CANARY_TARGET,
        "-p",
        "80,443",
        "--backend",
        "fake",
        "--scenario",
        "healthy",
        "--budget",
        "5000",
        "--out-dir",
        str(out_dir),
        "--label",
        CANARY_LABEL,
        "--notes",
        CANARY_NOTES,
        "--authorization",
        CANARY_AUTH,
        *extra,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:  # pragma: no cover - a failure here is a broken test setup
        raise AssertionError(f"scan failed ({proc.returncode}): {proc.stderr[-500:]}")
    runs = [p for p in out_dir.iterdir() if p.is_dir()]
    assert len(runs) == 1, f"expected one run directory, got {runs}"
    return runs[0]


def _scan_artifacts(out_dir: Path, *extra: str) -> tuple[Path, dict[str, str]]:
    run = _run_scan(out_dir, *extra)
    blobs = {
        path.name: path.read_text(encoding="utf-8", errors="replace")
        for path in run.iterdir()
        if path.is_file()
    }
    return run, blobs


def _hits(text: str) -> dict[str, int]:
    return {name: text.count(value) for name, value in CANARIES.items() if text.count(value)}


@tier(TIER_ORACLE)
class TestRedactionCoverage(unittest.TestCase):
    """The contract for what ``--redact`` does and does not cover."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="schedprobe-redact-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_without_redact_every_artifact_carries_the_target(self) -> None:
        # The control: proves the canaries actually reach the files, so the redacted run
        # below is testing redaction rather than testing a broken scan.
        _, blobs = _scan_artifacts(self.tmp / "plain", "--format", "json")
        self.assertIn("evidence.jsonl", blobs)
        self.assertIn("manifest.json", blobs)
        self.assertIn("results.json", blobs)
        # The label and the note live in the evidence log and nowhere else; the manifest
        # never carried them, redacted or not. Asserting per artifact keeps the control
        # meaningful instead of asserting a property the manifest never had.
        for name in ("evidence.jsonl", "manifest.json", "results.json"):
            self.assertIn(CANARY_TARGET, blobs[name], f"{name} should name the target")
        self.assertIn(CANARY_LABEL, blobs["evidence.jsonl"])
        self.assertIn(CANARY_NOTES, blobs["evidence.jsonl"])
        self.assertIn(CANARY_AUTH, blobs["evidence.jsonl"])

    def test_results_file_is_fully_pseudonymised(self) -> None:
        _, blobs = _scan_artifacts(self.tmp / "redacted", "--redact", "--format", "json")
        results = blobs["results.json"]
        for name, value in CANARIES.items():
            self.assertNotIn(value, results, f"{name} leaked into results.json")
        payload = json.loads(results)
        for row in payload["results"]:
            self.assertTrue(row["host"].startswith("h:"), row["host"])

    def test_manifest_does_not_leak_the_target_or_its_segment(self) -> None:
        # The manifest is a summary artifact: it is not an input to ``replay``, so
        # pseudonymising it costs nothing and leaks nothing that has to be there.
        _, blobs = _scan_artifacts(self.tmp / "manifest", "--redact", "--format", "json")
        manifest = blobs["manifest.json"]
        self.assertNotIn(CANARY_TARGET, manifest)
        self.assertNotIn("10.77.88.0/24", manifest, "the /24 segment is as identifying as the host")
        self.assertNotIn(CANARY_LABEL, manifest)
        self.assertNotIn(CANARY_NOTES, manifest)

    def test_evidence_log_declares_exactly_what_it_keeps(self) -> None:
        # The evidence log is allowed to keep real addresses, because replay re-derives
        # /24 segments from them. What is *not* allowed is keeping them silently: the
        # header must say so, machine-readably, next to the data itself.
        run, _ = _scan_artifacts(self.tmp / "log", "--redact", "--format", "json")
        header = next(
            record for record in read_records(run / "evidence.jsonl") if record.kind == "run-header"
        )
        redaction = header.data.get("redaction")
        self.assertIsNotNone(redaction, "run-header must carry a redaction block")
        self.assertTrue(redaction["requested"])
        self.assertEqual(redaction["evidence_log"], "plaintext")
        self.assertIn("console", redaction["scope"])
        self.assertIn("results", redaction["scope"])
        self.assertIn("manifest", redaction["scope"])
        self.assertNotIn("evidence", redaction["scope"])
        self.assertTrue(redaction["reason"], "the reason has to be stated, not implied")
        self.assertTrue(redaction["warning"])

    def test_unredacted_run_says_so(self) -> None:
        run, _ = _scan_artifacts(self.tmp / "noredact", "--format", "json")
        header = next(
            record for record in read_records(run / "evidence.jsonl") if record.kind == "run-header"
        )
        self.assertFalse(header.data["redaction"]["requested"])
        self.assertEqual(header.data["redaction"]["scope"], [])

    def test_pseudonyms_are_stable_within_a_run_and_unlinkable_across_runs(
        self,
    ) -> None:
        _, first = _scan_artifacts(self.tmp / "a", "--redact", "--format", "json")
        _, second = _scan_artifacts(self.tmp / "b", "--redact", "--format", "json")
        host_a = json.loads(first["results.json"])["results"][0]["host"]
        host_b = json.loads(second["results.json"])["results"][0]["host"]
        self.assertTrue(host_a.startswith("h:"))
        self.assertTrue(host_b.startswith("h:"))
        # The salt is the run id, so the same input host maps to a different pseudonym in
        # each run: two logs from the same client cannot be joined on the host field.
        self.assertNotEqual(host_a, host_b)


@tier(TIER_ORACLE)
class TestTamperDetection(unittest.TestCase):
    """Which edits the chain catches, and which it provably cannot."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="schedprobe-tamper-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "evidence.jsonl"
        with EvidenceLog(self.path, "run-tamper", truncate=True) as log:
            log.append("run-header", {"tool": "schedprobe", "targets": ["10.0.0.1"]})
            for index in range(6):
                log.append("probe", {"index": index, "host": "10.0.0.1", "port": 80 + index})
            log.append("summary", {"records": 6})
        self.assertEqual(verify_chain(self.path).ok, True)

    # --------------------------------------------------------------- detected
    def test_modified_record_is_detected(self) -> None:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[3])
        payload["data"]["port"] = 9999
        lines[3] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        status = verify_chain(self.path)
        self.assertFalse(status.ok)
        self.assertEqual(status.first_bad_seq, payload["seq"])

    def test_removed_middle_record_is_detected(self) -> None:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        del lines[3]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(verify_chain(self.path).ok)

    def test_reordered_records_are_detected(self) -> None:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[2], lines[3] = lines[3], lines[2]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(verify_chain(self.path).ok)

    def test_malformed_json_is_detected(self) -> None:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[2] = '{"seq": 2, "kind": "probe", "data": '
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        status = verify_chain(self.path)
        self.assertFalse(status.ok)
        self.assertTrue(status.reason)

    def test_foreign_run_id_is_detected(self) -> None:
        records = []
        for record in read_records(self.path):
            payload = {
                "seq": record.seq,
                "kind": record.kind,
                "data": record.data,
                "ts": record.ts,
                "run_id": "someone-elses-run",
                "prev": record.prev,
            }
            payload["hash"] = "sha256:" + sha256_hex(canonical_json(payload))
            records.append(canonical_json(payload))
        self.path.write_text("\n".join(records) + "\n", encoding="utf-8")
        self.assertFalse(verify_chain(self.path).ok)

    # ------------------------------------------------------------- not detected
    def test_truncated_tail_is_not_detectable_from_the_log_alone(self) -> None:
        # This is a *documented limitation*, pinned so nobody re-learns it the hard way.
        # Keeping only a prefix leaves a perfectly valid chain: every surviving record
        # still hashes to its own hash and points at its own predecessor. The missing
        # records are simply gone.
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:-3]) + "\n", encoding="utf-8")
        self.assertTrue(
            verify_chain(self.path).ok,
            "if this now fails, the chain gained a tail anchor - update the docs",
        )

    def test_manifest_digest_is_what_anchors_the_tail(self) -> None:
        # The mitigation: the manifest records the digest of the whole file *and* the
        # record count, and it is written separately, so a verifier holding both can
        # detect truncation even though the log cannot detect it alone.
        digest, size = file_digest(self.path)
        manifest = self.tmp / "manifest.json"
        write_manifest(self.tmp, {"evidence_sha256": digest, "evidence_bytes": size})
        self.assertTrue(manifest.is_file())
        recorded = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(recorded["evidence_sha256"], digest)

        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:-3]) + "\n", encoding="utf-8")
        after, after_size = file_digest(self.path)
        self.assertNotEqual(after, digest, "truncation must move the whole-file digest")
        self.assertLess(after_size, size)

    def test_whole_file_rewrite_is_not_detectable(self) -> None:
        # The chain is unkeyed SHA-256. Anyone who can write the file can also recompute
        # every hash, so a full rewrite produces a chain that verifies cleanly. This is
        # the honest boundary of the claim: the chain is tamper *evidence*, not tamper
        # *proof*, and the manifest only helps if the adversary cannot reach it too.
        attacker_log = self.tmp / "rewritten.jsonl"
        with EvidenceLog(attacker_log, "run-tamper", truncate=True) as log:
            log.append("run-header", {"tool": "schedprobe", "targets": ["10.0.0.1"]})
            for index in range(6):
                log.append("probe", {"index": index, "host": "10.0.0.1", "port": 80 + index})
            log.append("summary", {"records": 6})
        self.assertTrue(verify_chain(attacker_log).ok)
        # Identical shape, different digests: the log can be rebuilt from scratch at will.
        original, _ = file_digest(self.path)
        rewritten, _ = file_digest(attacker_log)
        self.assertNotEqual(original, rewritten)


@tier(TIER_ORACLE)
class TestRedactionIsNotDeletion(unittest.TestCase):
    """``--redact`` must be reversible *by the holder*, not by the reader."""

    def test_pseudonym_is_not_a_truncation_of_the_host(self) -> None:
        # A pseudonym that merely hides the last octet would be trivially recoverable by
        # sweeping a /24. Check the strong property instead: the mapping is a keyed hash,
        # so the same host cannot be recognised by its shape.
        first = redact(CANARY_TARGET, salt="run-a")
        second = redact(CANARY_TARGET, salt="run-b")
        self.assertNotEqual(first, second)
        self.assertNotIn("10.77.88", first)
        self.assertNotIn("88.9", first)
        self.assertEqual(first, redact(CANARY_TARGET, salt="run-a"))

    def test_canonical_json_is_stable_under_key_reordering(self) -> None:
        # The chain hash is computed over canonical JSON, so dict ordering must not change
        # the digest - otherwise the same logical record would verify differently
        # depending on which Python wrote it.
        left = canonical_json({"b": 1, "a": {"d": 2, "c": 3}})
        right = canonical_json({"a": {"c": 3, "d": 2}, "b": 1})
        self.assertEqual(left, right)
        self.assertEqual(
            hashlib.sha256(left.encode()).hexdigest(),
            hashlib.sha256(right.encode()).hexdigest(),
        )

    def test_unicode_survives_the_hash_round_trip(self) -> None:
        # Notes are free-form and will contain non-ASCII; the digest must be computed over
        # UTF-8 bytes, and the JSON must not be escaped into something that re-reads
        # differently.
        payload = {"notes": "扫描 10.0.0.0/24 — 已授权"}
        encoded = canonical_json(payload)
        # Readable on disk: a Chinese-speaking operator must be able to read back their
        # own audit log without a decoder. The serialization is still deterministic, which
        # is what the hash chain needs - see ``canonical_json``'s docstring.
        self.assertIn("扫描", encoded)
        self.assertIn("已授权", encoded)
        self.assertEqual(json.loads(encoded)["notes"], payload["notes"])
        self.assertEqual(encoded, canonical_json({"notes": payload["notes"]}))
        # And the digest covers the UTF-8 bytes that were actually written.
        self.assertEqual(
            sha256_hex(encoded),
            hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
