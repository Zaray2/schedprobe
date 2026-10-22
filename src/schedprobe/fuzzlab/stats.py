"""Typed view of the artefacts an AFL++ campaign leaves behind.

A fuzzing run produces its results as text files with a deceptively simple format
(``key : value``, padded). Parsing them into a typed record once, in one place, means the
report, the comparison and the evidence record all read the same numbers from the same
parse - instead of one of them quietly reading ``execs_done`` as a string and sorting
lexicographically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: Fields the report and the statistics need, with their types. Anything not listed is kept
#: in ``extra`` as text so a new AFL++ version cannot silently drop data.
_INT_FIELDS = (
    "execs_done",
    "execs_per_sec",
    "corpus_count",
    "saved_crashes",
    "saved_hangs",
    "edges_found",
    "total_edges",
    "cycles_done",
    "bitmap_cvg",
    "run_time",
    "last_update",
    "max_depth",
)
_FLOAT_FIELDS = ("execs_per_sec", "bitmap_cvg")

_LINE = re.compile(r"^(?P<key>[a-z_]+)\s*:\s*(?P<value>.*?)\s*$")


@dataclass(frozen=True, slots=True)
class RunStats:
    """One campaign's final statistics, plus what was needed to interpret them."""

    arm: str
    seed: int
    execs_done: int
    corpus_count: int
    saved_crashes: int
    saved_hangs: int
    edges_found: int
    total_edges: int
    cycles_done: int
    execs_per_sec: float
    coverage_percent: float
    runtime_s: int
    #: Every raw key/value pair, so nothing is lost to a schema change.
    raw: dict[str, str]

    @property
    def unique_edges(self) -> int:
        return self.edges_found

    def to_dict(self) -> dict[str, object]:
        return {
            "arm": self.arm,
            "seed": self.seed,
            "execs_done": self.execs_done,
            "corpus_count": self.corpus_count,
            "saved_crashes": self.saved_crashes,
            "saved_hangs": self.saved_hangs,
            "edges_found": self.edges_found,
            "total_edges": self.total_edges,
            "cycles_done": self.cycles_done,
            "execs_per_sec": round(self.execs_per_sec, 3),
            "coverage_percent": round(self.coverage_percent, 4),
            "runtime_s": self.runtime_s,
        }


def _as_int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _as_float(value: str) -> float:
    # AFL++ writes percentages as "38.88%" in some fields and bare numbers in others.
    text = value.strip().rstrip("%")
    try:
        return float(text)
    except (TypeError, ValueError):
        return 0.0


def parse_fuzzer_stats(text: str, *, arm: str = "", seed: int = 0) -> RunStats:
    """Parse the contents of AFL++'s ``fuzzer_stats`` file."""
    raw: dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.match(line)
        if match:
            raw[match.group("key")] = match.group("value")

    def as_int(key: str) -> int:
        return _as_int(raw.get(key, "0"))

    def as_float(key: str) -> float:
        return _as_float(raw.get(key, "0"))

    return RunStats(
        arm=arm,
        seed=seed,
        execs_done=as_int("execs_done"),
        corpus_count=as_int("corpus_count"),
        saved_crashes=as_int("saved_crashes"),
        saved_hangs=as_int("saved_hangs"),
        edges_found=as_int("edges_found"),
        total_edges=as_int("total_edges"),
        cycles_done=as_int("cycles_done"),
        execs_per_sec=as_float("execs_per_sec"),
        coverage_percent=as_float("bitmap_cvg"),
        runtime_s=as_int("run_time"),
        raw=raw,
    )


def read_fuzzer_stats(path: str | Path, *, arm: str = "", seed: int = 0) -> RunStats:
    """Read and parse a ``fuzzer_stats`` file.

    A missing file is an error rather than a zeroed record: a campaign that produced no
    stats did not run, and reporting it as "0 edges found" would turn a harness failure into
    a scientific result.
    """
    stats_path = Path(path)
    if not stats_path.is_file():
        raise FileNotFoundError(f"no fuzzer_stats at {stats_path}; the campaign did not run")
    return parse_fuzzer_stats(stats_path.read_text(encoding="utf-8", errors="replace"), arm=arm, seed=seed)
