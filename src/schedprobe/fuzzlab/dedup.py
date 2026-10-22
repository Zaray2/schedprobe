"""Crash deduplication by faulting-site signature.

A fuzzer counts *crashes*, not *defects*. One NULL dereference can be reached through twenty
different inputs and AFL++ will happily save twenty files, so `saved_crashes` overstates the
finding and inflates whichever arm happens to produce more variants of the same bug. Any
claim of the form "policy X found more defects" has to mean distinct faulting sites.

The signature is taken from what is actually observable in the crashing run's output:

* the ASAN/sanitizer classification (``heap-buffer-overflow``, ``SEGV``, ...);
* the top frame of the stack, minus addresses and offsets, because a rebuilt binary moves
  them and an address-based signature would make every run look unique;
* the signal for non-sanitizer aborts.

That is deliberately coarser than a full stack hash. A stack hash splits one bug into several
signatures when an inlining decision changes, and merging distinct-but-identical-looking
crashes is the lesser of the two errors here, because the report states the signature so a
reader can see how coarse it is.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

#: ``ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...``
_ASAN_KIND = re.compile(r"ERROR:\s+\w*Sanitizer:\s+(?P<kind>[A-Za-z0-9_-]+)")
#: ``#0 0x55f... in parse_object /src/cjson/cJSON.c:123:4``
_FRAME = re.compile(r"#(?P<index>\d+)\s+0x[0-9a-f]+\s+in\s+(?P<func>[^\s]+)\s+(?P<loc>\S+)")
#: ``Program received signal SIGSEGV`` / ``deadly signal: 11``
_SIGNAL = re.compile(r"(?:signal|Signal)[:\s]+(?P<sig>SIG[A-Z]+|\d+)")
#: ``DEADLYSIGNAL`` blocks emitted by ASAN on a hard fault
_DEADLY = re.compile(r"^(?P<kind>DEADLYSIGNAL)\b", re.M)
#: cJSON-style assertion from `abort()` under ASAN
_ABORT = re.compile(r"AddressSanitizer: ABRT|ABORTING", re.I)


@dataclass(frozen=True, slots=True)
class CrashRecord:
    """One crashing input, with enough to decide whether it is a new defect."""

    arm: str
    seed: int
    path: Path
    signature: str
    kind: str
    top_frame: str
    input_size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "arm": self.arm,
            "seed": self.seed,
            "file": self.path.name,
            "signature": self.signature,
            "kind": self.kind,
            "top_frame": self.top_frame,
            "input_size": self.input_size,
        }


def _strip_location(location: str) -> str:
    """``/src/cJSON.c:123:4`` -> ``/src/cJSON.c``; drops line and column."""
    return re.sub(r":\d+(?::\d+)?$", "", location)


def crash_signature(output: str) -> tuple[str, str, str]:
    """Return ``(signature, kind, top_frame)`` for a crashing run's combined output.

    ``kind`` is the sanitizer classification or the signal name; ``top_frame`` is the first
    frame with its address and offset removed. Both are returned separately because the
    report prints them: a signature alone would hide which part of the stack was used.
    """
    kind = ""
    match = _ASAN_KIND.search(output)
    if match:
        kind = match.group("kind")
    else:
        deadly = _DEADLY.search(output)
        if deadly:
            kind = deadly.group("kind")
        else:
            signal_match = _SIGNAL.search(output)
            if signal_match:
                kind = signal_match.group("sig")
            elif _ABORT.search(output):
                kind = "ABRT"

    top_frame = ""
    frame_match = _FRAME.search(output)
    if frame_match:
        top_frame = f"{frame_match.group('func')}@{_strip_location(frame_match.group('loc'))}"

    if not kind and not top_frame:
        # No recognisable fault: say so explicitly rather than letting everything collapse
        # into one signature and making the campaign look like a single defect.
        kind = "unknown"

    basis = f"{kind}|{top_frame}"
    signature = "sha256:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return signature, kind, top_frame


def read_crash_output(path: str | Path) -> str:
    """Read whatever a crash file contains.

    AFL++ saves the raw input for a crash, not the sanitizer output, so this returns the
    decoded input. The sanitizer output for a signature comes from replaying the input,
    which is what :func:`dedup_crashes` is given.
    """
    return Path(path).read_bytes().decode("utf-8", errors="replace")


def dedup_crashes(records: list[CrashRecord]) -> dict[str, list[CrashRecord]]:
    """Group crashes by signature, preserving the order the signatures first appeared."""
    grouped: dict[str, list[CrashRecord]] = {}
    for record in records:
        grouped.setdefault(record.signature, []).append(record)
    return grouped


def unique_defect_count(records: list[CrashRecord]) -> int:
    """How many distinct faulting sites the crashes represent."""
    return len({record.signature for record in records})
