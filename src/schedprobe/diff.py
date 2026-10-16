"""Run-to-run comparison with explicit anti-flap semantics.

The hard part of diffing two port scans is not the set arithmetic, it is not
lying. A port that answers differently on the second run has either genuinely
changed state or was always marginal (a packet drop, a rate limiter, a service
restart). This module refuses to guess: an entry whose two observations come from
*different verdicts* is reported as ``unstable`` with severity ``info`` and is
never promoted to ``new``/``disappeared`` unless a confirmation probe for the same
pair also agrees. The rules are visible in :data:`_CLASSIFICATION_RULES` and are
regression-tested in ``tests/test_reporting_cli.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .errors import EvidenceError
from .evidence import read_records
from .models import PortState, ProbeResult
from .util import canonical_json

__all__ = [
    "PortDelta",
    "DiffReport",
    "diff_states",
    "diff_runs",
    "states_from_chain",
    "scope_from_chains",
    "RULES_VERSION",
]

RULES_VERSION = "2024-11-anti-flap-1"

_EXPLAIN_CONFIRMED = "confirmed by a second agreeing observation"
_EXPLAIN_UNSTABLE_NO_CONFIRM = "verdict differs between runs and no second observation agreed"


@dataclass(frozen=True, slots=True)
class PortDelta:
    host: str
    port: int
    kind: str  # new | disappeared | changed | unstable
    severity: str  # high | medium | low | info
    before: str
    after: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "kind": self.kind,
            "severity": self.severity,
            "from": self.before,
            "to": self.after,
            "detail": self.detail,
        }

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.host}:{self.port} {self.before}->{self.after} [{self.kind}/{self.severity}]"


@dataclass(slots=True)
class DiffReport:
    left: str
    right: str
    deltas: list[PortDelta] = field(default_factory=list)
    only_left: int = 0
    only_right: int = 0
    common: int = 0
    rules_version: str = RULES_VERSION

    def by_kind(self, kind: str) -> list[PortDelta]:
        return [delta for delta in self.deltas if delta.kind == kind]

    @property
    def new(self) -> list[PortDelta]:
        return self.by_kind("new")

    @property
    def disappeared(self) -> list[PortDelta]:
        return self.by_kind("disappeared")

    @property
    def changed(self) -> list[PortDelta]:
        return self.by_kind("changed")

    @property
    def unstable(self) -> list[PortDelta]:
        return self.by_kind("unstable")

    @property
    def not_probed(self) -> list[PortDelta]:
        """Pairs outside the intersection of both runs' scope.

        Kept separate from ``new``/``disappeared`` on purpose: a port that only one run
        planned to probe is a *coverage* difference, not a change in the estate.
        """
        return self.by_kind("not-probed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "rules_version": self.rules_version,
            "only_left": self.only_left,
            "only_right": self.only_right,
            "common": self.common,
            "new": [d.to_dict() for d in self.new],
            "disappeared": [d.to_dict() for d in self.disappeared],
            "changed": [d.to_dict() for d in self.changed],
            "unstable": [d.to_dict() for d in self.unstable],
            "not_probed": [d.to_dict() for d in self.not_probed],
            "counts": {
                "new": len(self.new),
                "disappeared": len(self.disappeared),
                "changed": len(self.changed),
                "unstable": len(self.unstable),
                "not_probed": len(self.not_probed),
            },
        }


def _confirmed(states: Sequence[PortState]) -> bool:
    """True when at least two observations agree on a conclusive state."""
    conclusive = [state for state in states if state is not PortState.UNDETERMINED]
    return len(conclusive) >= 2 and len(set(conclusive)) == 1


def diff_states(
    left_states: Mapping[tuple[str, int], PortState],
    right_states: Mapping[tuple[str, int], PortState],
    *,
    left_history: Mapping[tuple[str, int], Sequence[PortState]] | None = None,
    right_history: Mapping[tuple[str, int], Sequence[PortState]] | None = None,
    left_label: str = "left",
    right_label: str = "right",
    scope: set[tuple[str, int]] | None = None,
) -> DiffReport:
    """Compare two port-state maps under the anti-flap rules.

    ``scope`` is the set of pairs *both* runs planned to probe. Pairs outside it were
    never in scope for one of the runs - typically because a smaller budget stopped the
    sweep early - and are reported as ``not-probed`` rather than as ``new`` or
    ``disappeared``. Without that distinction, comparing a 4k-budget run with a 150k one
    produces dozens of "new ports" that are simply ports the first run could not afford
    to reach.
    """
    report = DiffReport(left=left_label, right=right_label)
    left_keys = set(left_states)
    right_keys = set(right_states)
    report.only_left = len(left_keys - right_keys)
    report.only_right = len(right_keys - left_keys)
    report.common = len(left_keys & right_keys)

    def history(store, pair: tuple[str, int]) -> list[PortState]:
        if store is None:
            return []
        return list(store.get(pair, ()))

    for pair in sorted(left_keys | right_keys):
        before = left_states.get(pair, PortState.UNDETERMINED)
        after = right_states.get(pair, PortState.UNDETERMINED)
        if scope is not None and pair not in scope:
            report.deltas.append(
                PortDelta(
                    pair[0], pair[1], "not-probed", "info",
                    before.value, after.value,
                    "pair is outside the intersection of both runs' planned scope",
                )
            )
            continue
        if pair not in left_states:
            report.deltas.append(
                PortDelta(pair[0], pair[1], "new", "medium" if after is PortState.OPEN else "info",
                          "absent", after.value, "pair absent from the left run")
            )
            continue
        if pair not in right_states:
            report.deltas.append(
                PortDelta(pair[0], pair[1], "disappeared", "medium" if before is PortState.OPEN else "info",
                          before.value, "absent", "pair absent from the right run")
            )
            continue
        if before is after:
            continue
        before_hist = history(left_history, pair) + [before]
        after_hist = history(right_history, pair) + [after]
        if _confirmed(before_hist) and _confirmed(after_hist):
            kind = "changed"
            severity = "high" if PortState.OPEN in (before, after) else "low"
            detail = _EXPLAIN_CONFIRMED
        else:
            kind = "unstable"
            severity = "info"
            detail = _EXPLAIN_UNSTABLE_NO_CONFIRM
        report.deltas.append(
            PortDelta(pair[0], pair[1], kind, severity, before.value, after.value, detail)
        )
    report.deltas.sort(key=lambda d: (d.severity, d.kind, d.host, d.port))
    return report


def states_from_chain(
    path: str | Path,
) -> tuple[dict[tuple[str, int], PortState], dict[tuple[str, int], list[PortState]], dict[str, Any]]:
    """Return ``(final_state, observation_history, meta)`` for an evidence log.

    The *last* observation wins, and the full per-pair history is returned so the
    diff can apply its anti-flap rule without re-reading the file.
    """
    states: dict[tuple[str, int], PortState] = {}
    history: dict[tuple[str, int], list[PortState]] = {}
    meta: dict[str, Any] = {}
    for record in read_records(path):
        if record.kind == "run-header":
            meta = {
                "run_id": record.data.get("run_id"),
                "planner": record.data.get("planner"),
                "backend": record.data.get("backend", {}).get("backend"),
                "seed": record.data.get("seed"),
            }
        elif record.kind == "probe":
            try:
                result = ProbeResult.from_dict(dict(record.data["observation"]))
            except (KeyError, ValueError) as exc:
                raise EvidenceError("probe record is malformed", reason=str(exc)) from exc
            pair = (result.host, result.port)
            states[pair] = result.state
            history.setdefault(pair, []).append(result.state)
    if not states:
        raise EvidenceError("no probe observations found in evidence log", path=str(path))
    return states, history, meta


def scope_from_chains(paths: Sequence[str | Path]) -> set[tuple[str, int]]:
    """Per-run scope and completion state, keyed by evidence-log path.

    Returns the intersection of the pairs each run actually *observed*. A pair observed
    by only one run is then classified by whether the other run finished its sweep
    (``budget-stop.reason == "frontier-empty"``): if it did, the difference is real; if
    it ran out of budget or was stopped by pruning, the honest label is ``not-probed``.

    Without this, comparing a 4k-budget run against a 150k-budget run reports dozens of
    "newly opened ports" that are simply ports the first run could not afford to reach -
    the kind of false positive that erodes trust in a diff report.
    """
    observed: list[set[tuple[str, int]]] = []
    for path in paths:
        seen: set[tuple[str, int]] = set()
        for record in read_records(path):
            if record.kind == "probe":
                try:
                    seen.add((str(record.data["observation"]["host"]),
                              int(record.data["observation"]["port"])))
                except (KeyError, TypeError, ValueError):
                    continue
        observed.append(seen)
    if not observed:
        return set()
    scope = set(observed[0])
    for other in observed[1:]:
        scope &= other
    return scope


def diff_runs(left_dir: str | Path, right_dir: str | Path) -> DiffReport:
    """Compare two run directories (each must contain ``evidence.jsonl``)."""
    left_path = Path(left_dir)
    right_path = Path(right_dir)
    for candidate in (left_path, right_path):
        if candidate.is_dir() and not (candidate / "evidence.jsonl").is_file():
            raise EvidenceError("directory does not contain evidence.jsonl", path=str(candidate))
        if not candidate.exists():
            raise EvidenceError("run path does not exist", path=str(candidate))
    left_states, left_hist, left_meta = states_from_chain(
        left_path if left_path.is_file() else left_path / "evidence.jsonl"
    )
    right_states, right_hist, right_meta = states_from_chain(
        right_path if right_path.is_file() else right_path / "evidence.jsonl"
    )
    left_chain = left_path if left_path.is_file() else left_path / "evidence.jsonl"
    right_chain = right_path if right_path.is_file() else right_path / "evidence.jsonl"
    return diff_states(
        left_states,
        right_states,
        left_history=left_hist,
        right_history=right_hist,
        left_label=str(left_meta.get("run_id") or left_path),
        right_label=str(right_meta.get("run_id") or right_path),
        scope=scope_from_chains([left_chain, right_chain]),
    )


def write_diff(path: str | Path, report: DiffReport) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(canonical_json(report.to_dict()) + "\n", encoding="utf-8")
    return target


def severity_rank(severity: str) -> int:
    return {"high": 0, "medium": 1, "low": 2, "info": 3}.get(severity, 4)


def filter_deltas(deltas: Iterable[PortDelta], *, kinds: Sequence[str] | None = None,
                  min_severity: str = "info") -> list[PortDelta]:
    threshold = severity_rank(min_severity)
    out: list[PortDelta] = []
    for delta in deltas:
        if kinds and delta.kind not in kinds:
            continue
        if severity_rank(delta.severity) > threshold:
            continue
        out.append(delta)
    return out
