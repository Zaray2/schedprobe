"""Shareable derivative of an evidence log: redacted, and honest about it.

The evidence log is the audit record, and it keeps real addresses because a byte-exact
replay re-derives each host's /24 segment from the address itself (see the ``redaction``
block in the run header). That makes it the one artifact you cannot hand to a third party
- so this module produces a *derivative* instead, and labels it as one.

Three properties the derivative has that a hand-redacted copy would not:

1. **It says what it is.** ``redacted: true``, ``replayable: false``, and
   ``derivative_of`` naming the digest of the log it came from. A reader can tell at a
   glance that this is not the original, and a verifier can tell that ``replay`` will
   refuse it - because it will, and silently failing to replay is worse than saying so.

2. **The pseudonyms are not reversible by the reader.** ``--redact`` on the console keys
   its pseudonyms with the run id, and the run id is *inside the log*. Anyone holding the
   output can therefore brute-force a /24 in 256 attempts and recover the address. The
   export keys with a random salt that is **not written to the derivative**, and publishes
   only ``sha256(salt)`` so a holder can confirm which salt was used without being able to
   derive it. Pass ``--salt`` explicitly when you want reproducible pseudonyms or want to
   correlate an export with the console output of the run it came from.

3. **Free text is dropped by default.** ``--label``, ``--notes`` and ``--authorization``
   are whatever the operator typed, and ``--authorization`` is folded into ``notes``. They
   are replaced by a length marker unless ``--keep-notes`` is passed, because the usual
   reason to export is to show someone outside the engagement.

What it deliberately does **not** do: rewrite the hash chain. The derivative's records are
re-hashed over their redacted bodies, so the chain verifies *for the derivative*, and the
header states that this chain attests to the redacted content only. It is not, and must
never be presented as, evidence that the original log was untampered.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .evidence import (
    EvidenceLog,
    file_digest,
    read_records,
    utc_now_iso,
    verify_chain,
    write_manifest,
)
from .util import get_logger, sha256_hex

log = get_logger("schedprobe.export")

__all__ = ["EXPORT_SUFFIX", "ExportReport", "export_run", "redact_structure"]

EXPORT_SUFFIX = ".redacted.jsonl"

# Fields whose value is a host identifier even when it is a hostname rather than a
# literal, so the walker cannot rely on pattern-matching alone.
_HOST_KEYS = frozenset({"host", "hosts", "targets", "first_open"})
# Fields holding free-form operator text. The config carries it as ``run_label`` rather
# than ``label``, so an exact-name match misses it; the suffix rule catches both without
# turning into a guess about every key that happens to contain the substring.
_FREETEXT_NAMES = ("label", "notes", "authorization")
_FREETEXT_SUFFIXES = tuple(f"_{name}" for name in _FREETEXT_NAMES)
# Flags whose *value* is free text. Used when rewriting a recorded command line: an
# evidence log written by an older version still has the verbatim argv in it, and a
# derivative must not pass that on even though the current writer no longer produces it.
_FREETEXT_FLAGS = frozenset({"--label", "--notes", "--authorization"})
_SECRET_FLAGS = frozenset({"--token", "--password", "--api-key", "--secret"})

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV4_PORT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")
_CIDR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")


def _is_freetext_key(name: str) -> bool:
    lowered = name.lower()
    return lowered in _FREETEXT_NAMES or lowered.endswith(_FREETEXT_SUFFIXES)


@dataclass
class ExportReport:
    """What the export did, so the operator can see it rather than infer it."""

    source: Path
    log_path: Path
    manifest_path: Path
    salt: str
    salt_commitment: str
    salt_published: bool
    records: int
    redacted_values: int = 0
    dropped_text_fields: int = 0
    source_digest: str = ""
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "redacted_log": str(self.log_path),
            "manifest": str(self.manifest_path),
            "salt_commitment": self.salt_commitment,
            "salt_published": self.salt_published,
            "records": self.records,
            "redacted_values": self.redacted_values,
            "dropped_text_fields": self.dropped_text_fields,
            "source_digest": self.source_digest,
            "replayable": False,
            "limitations": list(self.limitations),
        }


class _Redactor:
    """Applies the pseudonym and free-text rules while walking a record body."""

    def __init__(self, salt: str, *, keep_notes: bool) -> None:
        self._salt = salt
        self._keep_notes = keep_notes
        self.redacted_values = 0
        self.dropped_text_fields = 0

    def pseudonym(self, host: str) -> str:
        digest = hmac.new(self._salt.encode("utf-8"), f"{host}:0".encode(), hashlib.sha256)
        return f"h:{digest.hexdigest()[:12]}"

    def _rewrite_string(self, text: str) -> str:
        """Replace every address-shaped substring, longest pattern first."""
        changed = False

        def cidr(match: re.Match[str]) -> str:
            nonlocal changed
            changed = True
            network, _, prefix = match.group(0).partition("/")
            # Keep the prefix length: it is useful context and not identifying by itself.
            return f"{self.pseudonym(network)}/{prefix}"

        def host_port(match: re.Match[str]) -> str:
            nonlocal changed
            changed = True
            host, _, port = match.group(0).rpartition(":")
            return f"{self.pseudonym(host)}:{port}"

        def bare(match: re.Match[str]) -> str:
            nonlocal changed
            changed = True
            return self.pseudonym(match.group(0))

        out = _CIDR.sub(cidr, text)
        out = _IPV4_PORT.sub(host_port, out)
        out = _IPV4.sub(bare, out)
        if changed:
            self.redacted_values += 1
        return out

    def _rewrite_argv(self, values: list[Any]) -> list[Any]:
        """Redact the values of free-text and secret flags inside a recorded command line.

        The exporter cannot assume the source log was written by the current version, so
        it re-applies the rule rather than trusting the writer to have applied it.
        """
        out: list[Any] = []
        drop_next = False
        for item in values:
            if drop_next:
                out.append("<redacted>")
                drop_next = False
                continue
            if isinstance(item, str):
                name = item.lower().split("=", 1)[0]
                if name in _FREETEXT_FLAGS or name in _SECRET_FLAGS:
                    if "=" in item:
                        out.append(f"{item.split('=', 1)[0]}=<redacted>")
                    else:
                        out.append(item)
                        drop_next = True
                    self.dropped_text_fields += 1
                    continue
            out.append(self.walk(item))
        return out

    def walk(self, value: Any, *, key: str = "") -> Any:
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for raw_key, raw_value in value.items():
                name = str(raw_key)
                if name.lower() == "argv" and isinstance(raw_value, list):
                    out[name] = self._rewrite_argv(list(raw_value))
                    continue
                if not self._keep_notes and _is_freetext_key(name) and isinstance(raw_value, str):
                    self.dropped_text_fields += 1
                    out[name] = f"<redacted: {len(raw_value)} chars>"
                    continue
                new_key = self._rewrite_string(name) if _IPV4.search(name) else name
                out[new_key] = self.walk(raw_value, key=name)
            return out
        if isinstance(value, list):
            return [self.walk(item, key=key) for item in value]
        if isinstance(value, str):
            if key in _HOST_KEYS:
                # Named as a host: pseudonymise the whole value, whether or not it looks
                # like a literal, so a hostname target is not left in the clear.
                if value:
                    self.redacted_values += 1
                    return self.pseudonym(value)
                return value
            return self._rewrite_string(value)
        return value


def redact_structure(payload: Any, *, salt: str, keep_notes: bool = False) -> tuple[Any, int, int]:
    """Redact a JSON-shaped structure.

    Returns ``(redacted, redacted_values, dropped_text_fields)``. Exposed separately from
    :func:`export_run` so the rules can be tested against a hand-written structure without
    producing a run first.
    """
    redactor = _Redactor(salt, keep_notes=keep_notes)
    result = redactor.walk(payload)
    return result, redactor.redacted_values, redactor.dropped_text_fields


def _header_block(
    *, source_digest: str, salt_commitment: str, source_run_id: str, keep_notes: bool
) -> dict[str, Any]:
    """The declaration that makes the derivative un-mistakable for what it is."""
    return {
        "derivative": True,
        "derivative_of": source_digest,
        "derivative_of_run_id": source_run_id,
        "replayable": False,
        "replay_note": (
            "this log cannot be replayed: pseudonymising the host identifiers removes the "
            "addresses that a replay re-derives each /24 segment from, so feeding it to "
            "`schedprobe replay` will report divergence by design rather than a defect"
        ),
        "redaction": {
            "applied": True,
            "scope": ["host_identifiers", "segments", "free_text_fields"],
            "pseudonym": "hmac-sha256(unpublished_salt, host)[:12] prefixed with 'h:'",
            "salt_commitment": salt_commitment,
            "salt_published": False,
            "free_text": "kept" if keep_notes else "replaced by a length marker",
        },
        "limitations": [
            "the chain below attests to the redacted content only; it is NOT evidence that "
            "the original log was untampered",
            "timestamps are unchanged and still reveal when the run happened",
            "port numbers and timings are unchanged; a host can sometimes be re-identified "
            "from an unusual port/timing fingerprint",
        ],
    }


def export_run(
    source: str | Path,
    out_path: str | Path,
    *,
    salt: str = "",
    keep_notes: bool = False,
) -> ExportReport:
    """Write a redacted, explicitly non-replayable derivative of ``source``.

    ``source`` is a run directory or an ``evidence.jsonl``. The derivative is written to
    ``out_path`` (defaulting to ``<source>.redacted.jsonl`` next to the original) and a
    matching manifest beside it.
    """
    source_path = Path(source)
    if source_path.is_dir():
        source_path = source_path / "evidence.jsonl"
    if not source_path.is_file():
        raise EvidenceError("evidence log not found", path=str(source_path))

    status = verify_chain(source_path)
    if not status.ok:
        # Refusing here is deliberate: exporting a log that does not verify would launder
        # a broken record into a clean-looking derivative.
        raise EvidenceError(
            "refusing to export an evidence log that does not verify",
            path=str(source_path),
            reason=status.reason,
        )

    source_digest, _ = file_digest(source_path)
    use_salt = salt or secrets.token_hex(16)
    salt_commitment = "sha256:" + sha256_hex(use_salt)
    out_file = Path(out_path)
    if out_file.is_dir() or not out_file.suffix:
        out_file = out_file / (source_path.stem + EXPORT_SUFFIX)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if out_file.exists():
        raise EvidenceError("refusing to overwrite an existing file", path=str(out_file))

    records = list(read_records(source_path))
    source_run_id = records[0].run_id if records else ""
    redacted_count = 0
    dropped = 0

    with EvidenceLog(out_file, f"{source_run_id}-redacted", truncate=True) as out_log:
        out_log.append(
            "run-header",
            {
                **_header_block(
                    source_digest=source_digest,
                    salt_commitment=salt_commitment,
                    source_run_id=source_run_id,
                    keep_notes=keep_notes,
                ),
                "tool": "schedprobe",
                "exported_at": utc_now_iso(),
            },
        )
        for record in records:
            body, hits, drops = redact_structure(record.data, salt=use_salt, keep_notes=keep_notes)
            redacted_count += hits
            dropped += drops
            out_log.append(f"source-{record.kind}", {"source_seq": record.seq, "data": body})
        out_log.append(
            "export-summary",
            {
                "source_records": len(records),
                "redacted_values": redacted_count,
                "dropped_text_fields": dropped,
                "source_digest": source_digest,
            },
        )

    derivative_digest, derivative_bytes = file_digest(out_file)
    manifest_path = write_manifest(
        out_file.parent,
        {
            "tool": "schedprobe",
            "kind": "redacted-export",
            "derivative_of": source_digest,
            "derivative_of_run_id": source_run_id,
            "evidence_file": out_file.name,
            "evidence_sha256": derivative_digest,
            "evidence_bytes": derivative_bytes,
            "evidence_records": out_log.count,
            "replayable": False,
            "redacted_values": redacted_count,
            "dropped_text_fields": dropped,
            "generated_at": utc_now_iso(),
        },
    )
    # ``write_manifest`` always targets ``manifest.json``; give the export its own name so
    # it can sit next to the original without clobbering the original's manifest.
    final_manifest = out_file.parent / (out_file.stem + ".manifest.json")
    if manifest_path != final_manifest:
        shutil.move(str(manifest_path), str(final_manifest))

    log.info(
        "exported a redacted derivative: %d records, %d values redacted",
        out_log.count,
        redacted_count,
    )
    return ExportReport(
        source=source_path,
        log_path=out_file,
        manifest_path=final_manifest,
        salt=use_salt,
        salt_commitment=salt_commitment,
        salt_published=False,
        records=out_log.count,
        redacted_values=redacted_count,
        dropped_text_fields=dropped,
        source_digest=source_digest,
        limitations=[
            "not replayable by design",
            "chain attests to the redacted content only",
            "timestamps and ports are unchanged",
        ],
    )
