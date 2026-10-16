"""Hash-chained, append-only evidence log.

Design
------
Each record is one line of JSON with this shape::

    {"seq": 7, "hash": "sha256:...", "prev": "sha256:...", "kind": "probe",
     "run_id": "...", "ts": "2026-01-01T00:00:00.000+00:00", "data": {...}}

``hash`` is ``sha256(canonical_json(record_without_hash))``. ``prev`` is the
``hash`` of the previous record; the first record uses a genesis value derived
from the run id, so two different runs can never share a chain head.

Why bother: a scan report is evidence. If a reviewer cannot tell whether a line
was inserted, deleted or edited after the fact, the report is worth very little.
``verify_chain`` recomputes the whole chain and localizes the first bad record.
This is tamper *evidence*, not tamper *proof* - an attacker who can rewrite the
whole file can also rewrite the chain, which is why the run also emits a manifest
with the file digest that is meant to be stored or shared separately.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from .errors import EvidenceError
from .util import canonical_json, sha256_hex

__all__ = [
    "GENESIS_PREFIX",
    "ChainStatus",
    "EvidenceLog",
    "EvidenceRecord",
    "decision_timeline",
    "file_digest",
    "observation_timeline",
    "read_records",
    "reason_histogram",
    "status_to_dict",
    "utc_now_iso",
    "verify_chain",
    "write_manifest",
]

GENESIS_PREFIX = "sha256:schedprobe-genesis:"
DEFAULT_FILENAME = "evidence.jsonl"
MANIFEST_FILENAME = "manifest.json"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    seq: int
    kind: str
    data: Mapping[str, Any]
    ts: str
    run_id: str
    prev: str
    hash: str

    def body(self) -> dict[str, Any]:
        """The exact mapping that gets hashed (``hash`` excluded)."""
        return {
            "seq": self.seq,
            "kind": self.kind,
            "data": _plain(self.data),
            "ts": self.ts,
            "run_id": self.run_id,
            "prev": self.prev,
        }

    def to_json(self) -> str:
        return canonical_json({**self.body(), "hash": self.hash})

    @classmethod
    def from_json(cls, line: str) -> EvidenceRecord:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"evidence line is not valid JSON: {exc}", line=line[:120]) from exc
        for key in ("seq", "kind", "data", "ts", "run_id", "prev", "hash"):
            if key not in payload:
                raise EvidenceError("evidence record is missing a required field", field=key)
        return cls(
            seq=int(payload["seq"]),
            kind=str(payload["kind"]),
            data=payload["data"],
            ts=str(payload["ts"]),
            run_id=str(payload["run_id"]),
            prev=str(payload["prev"]),
            hash=str(payload["hash"]),
        )


def _plain(value: Any) -> Any:
    """Convert dataclasses/enums/tuples into JSON-native structures deterministically."""
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _plain(to_dict())
    if hasattr(value, "value"):  # enum
        return _plain(value.value)
    raise EvidenceError("value is not serializable for the evidence log", type=type(value).__name__)


class EvidenceLog:
    """Append-only writer that maintains the hash chain.

    The file is opened with ``O_APPEND`` and flushed after every record so that a
    crashed run still leaves a verifiable prefix of the chain rather than a lost
    buffer.
    """

    def __init__(self, path: str | os.PathLike[str], run_id: str, *, truncate: bool = False) -> None:
        self.path = Path(path)
        self.run_id = run_id
        self._seq = 0
        self._prev = GENESIS_PREFIX + sha256_hex(run_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if truncate else "a"
        if self.path.exists() and not truncate and self.path.stat().st_size > 0:
            # Reopening an existing chain: adopt its tail so we never fork it.
            last = None
            for last in read_records(self.path):  # noqa: B007 - we want the tail
                pass
            if last is not None:
                if last.run_id != run_id:
                    raise EvidenceError(
                        "refusing to append to a chain from a different run",
                        existing_run=last.run_id,
                        new_run=run_id,
                    )
                self._seq = last.seq
                self._prev = last.hash
        # The handle lives for the whole object lifetime on purpose: the chain is
        # appended to record by record and must stay open across many writes, so a
        # ``with`` block per record would cost an open/close pair per line. ``close``,
        # ``__exit__`` and the CLI's error paths all close it.
        self._handle = open(  # noqa: SIM115
            self.path, mode, encoding="utf-8", newline="\n"
        )

    # ------------------------------------------------------------------ context
    def __enter__(self) -> EvidenceLog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()

    # ------------------------------------------------------------------- writing
    @property
    def head(self) -> str:
        return self._prev

    @property
    def count(self) -> int:
        return self._seq

    @property
    def closed(self) -> bool:
        return self._handle.closed

    def append(self, kind: str, data: Mapping[str, Any], *, ts: str | None = None) -> EvidenceRecord:
        if not kind or not isinstance(kind, str):
            raise EvidenceError("evidence record kind must be a non-empty string")
        record = EvidenceRecord(
            seq=self._seq + 1,
            kind=kind,
            data=data,
            ts=ts or utc_now_iso(),
            run_id=self.run_id,
            prev=self._prev,
            hash="",
        )
        digest = "sha256:" + sha256_hex(canonical_json(record.body()))
        record = EvidenceRecord(
            seq=record.seq,
            kind=record.kind,
            data=record.data,
            ts=record.ts,
            run_id=record.run_id,
            prev=record.prev,
            hash=digest,
        )
        self._handle.write(record.to_json() + "\n")
        self._handle.flush()
        self._seq = record.seq
        self._prev = digest
        return record


def read_records(path: str | os.PathLike[str]) -> Iterator[EvidenceRecord]:
    """Yield records from a chain file, skipping blank lines only."""
    file_path = Path(path)
    if not file_path.is_file():
        raise EvidenceError("evidence log not found", path=str(file_path))
    with open(file_path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield EvidenceRecord.from_json(stripped)
            except EvidenceError as exc:
                raise EvidenceError(f"broken at line {number}: {exc.message}", line=number) from exc


@dataclass(slots=True)
class _ReadFailure:
    """Marker yielded by :func:`_read_records_lenient` when the stream breaks."""

    message: str
    line: int | None


@dataclass(slots=True)
class ChainStatus:
    ok: bool
    records: int
    run_id: str
    head: str
    first_bad_seq: int | None = None
    reason: str = ""
    kinds: dict[str, int] | None = None


def _read_records_lenient(
    path: str | os.PathLike[str],
) -> Iterator[EvidenceRecord | _ReadFailure]:
    """Yield records, turning a mid-stream failure into one final marker object.

    Lets :func:`verify_chain` stay total *and* streaming: the caller sees the valid
    prefix, then a single object saying where the log stopped being readable. Materialising
    the whole file to catch the exception would defeat the streaming reader, and a hash
    chain over a 30 MB log is exactly the case where that matters.
    """
    stream = read_records(path)
    while True:
        try:
            record = next(stream)
        except StopIteration:
            return
        except EvidenceError as exc:
            line = exc.context.get("line")
            yield _ReadFailure(exc.message, int(line) if isinstance(line, int) else None)
            return
        yield record


def verify_chain(path: str | os.PathLike[str]) -> ChainStatus:
    """Recompute the chain and report the first inconsistency, if any.

    This function is **total**: it reports a broken log as ``ok=False`` rather than
    raising. A verifier that sometimes returns a status and sometimes throws is a bad
    contract, and the case that makes it obvious is the one that matters most - a log
    that has been corrupted. ``read_records`` still raises, because a caller that asked
    for records genuinely cannot continue; this wrapper turns that into a verdict.
    """
    expected_prev: str | None = None
    expected_seq = 0
    run_id = ""
    head = ""
    kinds: dict[str, int] = {}
    count = 0
    for record in _read_records_lenient(path):
        if isinstance(record, _ReadFailure):
            where = f" at line {record.line}" if record.line else ""
            return ChainStatus(
                False,
                count,
                run_id,
                head,
                record.line,
                f"unreadable{where}: {record.message}",
                kinds,
            )
        if expected_prev is None:
            run_id = record.run_id
            expected_prev = GENESIS_PREFIX + sha256_hex(run_id)
            if record.prev != expected_prev:
                return ChainStatus(
                    False,
                    1,
                    run_id,
                    record.hash,
                    record.seq,
                    "genesis mismatch: first record does not chain from the run id",
                )
        if record.seq != expected_seq + 1:
            return ChainStatus(
                False,
                count,
                run_id,
                head,
                record.seq,
                f"sequence discontinuity: expected {expected_seq + 1}, got {record.seq}",
            )
        if record.prev != expected_prev:
            return ChainStatus(
                False,
                count,
                run_id,
                head,
                record.seq,
                "previous-hash mismatch: a record was inserted, removed or reordered",
            )
        recomputed = "sha256:" + sha256_hex(canonical_json(record.body()))
        if recomputed != record.hash:
            return ChainStatus(
                False,
                count,
                run_id,
                head,
                record.seq,
                "record digest mismatch: the record body was modified after writing",
            )
        if record.run_id != run_id:
            return ChainStatus(False, count, run_id, head, record.seq, "run id changed mid-chain")
        kinds[record.kind] = kinds.get(record.kind, 0) + 1
        expected_seq = record.seq
        expected_prev = record.hash
        head = record.hash
        count += 1
    if count == 0:
        return ChainStatus(False, 0, "", "", None, "evidence log is empty")
    return ChainStatus(True, count, run_id, head, None, "", kinds)


def file_digest(path: str | os.PathLike[str]) -> tuple[str, int]:
    """Return ``(sha256, size_bytes)`` of a file, streaming so large logs are fine."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return "sha256:" + digest.hexdigest(), size


def write_manifest(out_dir: str | os.PathLike[str], payload: Mapping[str, Any]) -> Path:
    """Write ``manifest.json`` atomically (temp file + ``os.replace``)."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / MANIFEST_FILENAME
    tmp = directory / (MANIFEST_FILENAME + f".tmp{os.getpid()}")
    body = dict(payload)
    body.setdefault("generated_at", utc_now_iso())
    tmp.write_text(json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    return target


def monotonic() -> float:
    return time.monotonic()


def _as_int(value: object, default: int) -> int:
    """Coerce an untrusted JSON value to ``int``, falling back instead of raising.

    Every value that comes back out of an evidence log is ``Any``: the log is a file on
    disk and may have been written by an older version, hand-edited, or corrupted. The
    timeline builders therefore go through here rather than calling ``int()`` directly.
    """
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, (float, str)):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def observation_timeline(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Extract observations (what actually happened), in commit order.

    This is the data behind ``schedprobe verify``'s replay and ``schedprobe diff``:
    one row per probe that ran, carrying the pair, the state and the cost. It is
    deliberately independent of the scheduler's decisions, so a replay can apply
    the observations to a fresh planner.
    """
    rows: list[dict[str, Any]] = []
    for record in read_records(path):
        if record.kind != "probe":
            continue
        dispatched = dict(record.data.get("dispatched", {}))
        observation = dict(record.data.get("observation", {}))
        rows.append(
            {
                "seq": record.seq,
                "host": str(dispatched.get("host", observation.get("host"))),
                "port": _as_int(dispatched.get("port", observation.get("port")), 0),
                "reason": dispatched.get("reason"),
                "timeout_s": dispatched.get("executed_timeout_s", dispatched.get("timeout_s")),
                "attempt": dispatched.get("attempt", observation.get("attempt", 1)),
                "is_confirmation": bool(dispatched.get("is_confirmation", False)),
                "state": observation.get("state"),
                "verdict": observation.get("verdict"),
                "confidence": observation.get("confidence"),
                "cost": observation.get("cost_units"),
                "detail": observation.get("detail"),
                "cost_spent": record.data.get("cost_spent"),
                "live_pairs": record.data.get("live_pairs"),
                "planner_generation": record.data.get("planner_generation"),
                "plan_refreshed": "plan_refresh" in record.data,
            }
        )
    return rows


def decision_timeline(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Extract the scheduler's decisions from a chain, in order.

    Each probe record stores both what ran (``dispatched``) and what the scheduler
    chose next (``decision``). This function returns one row per decision, joined
    with the observation that preceded it, so a reader can see the causal chain:
    observation -> updated frontier -> next decision -> the cost that decision
    implied.
    """
    rows: list[dict[str, Any]] = []
    for record in read_records(path):
        if record.kind != "probe":
            continue
        dispatched = dict(record.data.get("dispatched", {}))
        observation = dict(record.data.get("observation", {}))
        scheduled_pair = str(dispatched.get("host", observation.get("host")))
        scheduled_port = _as_int(dispatched.get("port", observation.get("port")), 0)
        rows.append(
            {
                "seq": record.seq,
                "host": scheduled_pair,
                "port": scheduled_port,
                "state": observation.get("state"),
                "verdict": observation.get("verdict"),
                "confidence": observation.get("confidence"),
                "cost": observation.get("cost_units"),
                "scheduled_reason": dispatched.get("reason"),
                "scheduled_timeout_s": dispatched.get("executed_timeout_s", dispatched.get("timeout_s")),
                "attempt": dispatched.get("attempt", 1),
                "is_confirmation": bool(dispatched.get("is_confirmation", False)),
                "cost_spent": record.data.get("cost_spent"),
                "live_pairs": record.data.get("live_pairs"),
                "planner_generation": record.data.get("planner_generation"),
                "plan_refreshed": "plan_refresh" in record.data,
                "next_reason": (record.data.get("decision") or {}).get("reason"),
                "next_host": (record.data.get("decision") or {}).get("host"),
                "next_port": (record.data.get("decision") or {}).get("port"),
                "next_timeout_s": (record.data.get("decision") or {}).get("timeout_s"),
            }
        )
    return rows


def reason_histogram(rows: Iterable[Any]) -> dict[str, int]:
    """Count scheduling reasons.

    Accepts either an iterable of mappings (with a ``reason`` key or a caller-chosen
    key) or a plain iterable of reason strings, so both the timeline rows and a raw
    column can be fed in without a conversion step.
    """
    counts: dict[str, int] = {}
    for row in rows:
        if isinstance(row, Mapping):
            key = str(row.get("reason") or row.get("scheduled_reason") or "unknown")
        elif row is None:
            key = "unknown"
        else:
            key = str(row)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def status_to_dict(path: str | os.PathLike[str], status: ChainStatus) -> dict[str, Any]:
    return {
        "path": str(path),
        "ok": status.ok,
        "records": status.records,
        "run_id": status.run_id,
        "head": status.head,
        "first_bad_seq": status.first_bad_seq,
        "reason": status.reason,
        "kinds": status.kinds or {},
    }
