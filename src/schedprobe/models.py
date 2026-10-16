"""Domain model: ports, probe outcomes, segment state, and run-level verdicts.

Every value object here is immutable (``frozen=True`` dataclasses) except
:class:`SegmentState`, which is mutated in place by the planner because the
planner is explicitly a stateful online decision maker. That asymmetry is
deliberate: probe observations are facts and must not be edited, while segment
health is a running estimate and must be.
"""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

__all__ = [
    "PlannedProbe",
    "PortState",
    "ProbeResult",
    "SegmentState",
    "Verdict",
    "normalize_target",
    "segment_of",
]


class PortState(enum.StrEnum):
    """TCP port state as understood by this tool.

    ``UNDETERMINED`` is a first-class outcome: the scheduler must never silently
    downgrade an inconclusive probe into ``CLOSED``. That distinction is what the
    confidence-based confirmation pass (see ``planners/adaptive.py``) exists for.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNDETERMINED = "undetermined"

    @property
    def is_conclusive(self) -> bool:
        return self is not PortState.UNDETERMINED


class Verdict(enum.StrEnum):
    """How a port state was decided - the *why*, not the *what*.

    This is the field that makes a scan report re-readable months later.
    """

    CONNECTED = "connected"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    HOST_UNREACHABLE = "host-unreachable"
    RESET = "reset"
    ERROR = "error"
    CONFIRMED_TIMEOUT = "confirmed-timeout"
    UNRESOLVED = "unresolved"
    NOT_PROBED = "not-probed"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """A single observation of one (host, port) pair.

    ``cost_units`` is backend-supplied and intentionally abstract: the simulation
    backend returns a deterministic integer, the real network backend returns
    milliseconds. The planner only ever compares costs within one run, so mixing
    units across backends would be a bug - :class:`~schedprobe.engine.ScanEngine`
    records the unit on the run record to make that visible.
    """

    host: str
    port: int
    state: PortState
    verdict: Verdict
    cost_units: int
    confidence: float
    attempt: int = 1
    detail: str = ""

    def __post_init__(self) -> None:
        if not 0 < self.port < 65536:
            raise ValueError(f"port out of range: {self.port}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")
        if self.cost_units < 0:
            raise ValueError(f"cost_units must be >= 0, got {self.cost_units}")

    @property
    def decisive(self) -> bool:
        """True when this single observation is enough to stop probing the pair."""
        return self.state is not PortState.UNDETERMINED and self.confidence >= 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state.value,
            "verdict": self.verdict.value,
            "cost_units": self.cost_units,
            "confidence": round(self.confidence, 4),
            "attempt": self.attempt,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ProbeResult:
        return cls(
            host=str(payload["host"]),
            port=int(payload["port"]),
            state=PortState(payload["state"]),
            verdict=Verdict(payload["verdict"]),
            cost_units=int(payload["cost_units"]),
            confidence=float(payload["confidence"]),
            attempt=int(payload.get("attempt", 1)),
            detail=str(payload.get("detail", "")),
        )


@dataclass(frozen=True, slots=True)
class PlannedProbe:
    """A scheduler decision to probe one pair.

    ``reason`` is a short stable token (not prose) so it can be aggregated in
    reports; ``priority`` is the score the planner used, recorded for post-hoc
    analysis of *why* this probe came before another.
    """

    host: str
    port: int
    reason: str
    priority: float
    timeout_s: float
    is_confirmation: bool = False

    @property
    def pair(self) -> tuple[str, int]:
        return (self.host, self.port)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "reason": self.reason,
            "priority": round(self.priority, 6),
            "timeout_s": round(self.timeout_s, 6),
            "is_confirmation": self.is_confirmation,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> PlannedProbe:
        return cls(
            host=str(payload["host"]),
            port=int(payload["port"]),
            reason=str(payload["reason"]),
            priority=float(payload["priority"]),
            timeout_s=float(payload["timeout_s"]),
            is_confirmation=bool(payload.get("is_confirmation", False)),
        )


@dataclass(slots=True)
class SegmentState:
    """Running health estimate for one network segment (a /24 by default).

    The adaptive planner keeps one of these per segment and uses
    :meth:`health_score` to decide where the next cost unit goes. All counters are
    plain integers/floats so that a replay from the evidence log reproduces them
    bit for bit.
    """

    segment: str
    hosts: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    planned: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    undetermined_count: int = 0
    cost_spent: int = 0
    consecutive_refusals: int = 0
    consecutive_timeouts: int = 0
    pruned: bool = False
    prune_reason: str = ""
    deferred: bool = False
    confidence_ema: float = 0.5
    extra_budget: int = 0

    @property
    def budget(self) -> int:
        return self.cost_spent + self.extra_budget

    def observe(self, result: ProbeResult) -> None:
        """Fold one probe result into the segment health estimate."""
        self.cost_spent += result.cost_units
        if result.state is PortState.OPEN:
            self.open_count += 1
            self.consecutive_refusals = 0
            self.consecutive_timeouts = 0
        elif result.state is PortState.CLOSED:
            self.closed_count += 1
            self.consecutive_refusals += 1
            self.consecutive_timeouts = 0
        elif result.state is PortState.FILTERED:
            self.filtered_count += 1
            self.consecutive_refusals = 0
            self.consecutive_timeouts += 1
        else:
            self.undetermined_count += 1
            self.consecutive_refusals = 0
            self.consecutive_timeouts = 0
        # EMA over per-observation confidence; alpha=0.3 keeps the estimate
        # responsive without letting a single outlier redefine the segment.
        self.confidence_ema = round(0.7 * self.confidence_ema + 0.3 * result.confidence, 6)

    def health_score(self, timeout_penalty: float = 1.0) -> float:
        """Return a score where **lower means 'probe me sooner'**.

        History note: the first version of this function was
        ``confidence_ema * sqrt(1 + productive) - timeout_penalty * waste_ratio``
        and the benchmark showed it was actively harmful - it pushed the *healthy*
        hosts of a filtered segment up the queue (their low segment confidence made
        the score small) while making quiet-but-fine segments look expensive. The
        published results in ``docs/research/benchmark-results.md`` are from the
        current formula; the benchmark harness is what caught the old one.

        Current rules, in words:

        * a segment that has only ever produced timeouts is the worst possible
          place to spend budget, so it scores high (0.25 + a monotone term);
        * a segment whose probes have been answered quickly and cheaply scores
          close to zero, and keeps accruing a bonus for each open/closed result;
        * the penalty is scaled by how much of the segment's budget was burned on
          timeouts, so one slow host does not condemn a whole /24.

        The result is unit-less; only the ordering and the seeding of the heap
        matter, plus the requirement that it stays deterministic.
        """
        denominator = max(1, self.planned)
        waste_ratio = self.filtered_count / denominator
        answered = self.open_count + self.closed_count
        # Coverage term: how much of this segment has never been probed. It exists
        # because without it the start-up batch is filled strictly by segment order,
        # so a run can spend its whole first wave inside one segment before learning
        # anything about the others. The benchmark's `blackhole-segment` case is what
        # exposed that: 20 of the first 22 probes went into the dead /24.
        # It is a small bonus (<= 0.2) so detection quality and liveness still decide.
        coverage_bonus = 0.2 * max(0.0, 1.0 - (answered + self.filtered_count) / denominator)
        if answered == 0:
            if self.filtered_count > 0:
                # Only timeouts so far: productive-but-quiet is still better than
                # this, so it must rank behind a segment we simply have not tried.
                return round(0.75 + timeout_penalty * waste_ratio * 0.25, 6)
            # Untested. Deliberately worse than any segment that has answered even
            # one probe (see the branch below), because the planner has no evidence
            # and should spend its next probe where it has some.
            return round(0.5 - coverage_bonus, 6)
        productive = answered / denominator
        base = 1.0 - self.confidence_ema * productive
        penalty = timeout_penalty * waste_ratio * 0.5
        return round(max(0.0, base + penalty - coverage_bonus), 6)

    def as_dict(self) -> dict[str, Any]:
        return {
            "segment": self.segment,
            "hosts": list(self.hosts),
            "ports_total": len(self.ports),
            "planned": self.planned,
            "open": self.open_count,
            "closed": self.closed_count,
            "filtered": self.filtered_count,
            "undetermined": self.undetermined_count,
            "cost_spent": self.cost_spent,
            "confidence_ema": round(self.confidence_ema, 6),
            "health_score": self.health_score(),
            "pruned": self.pruned,
            "deferred": self.deferred,
            "prune_reason": self.prune_reason,
        }

    def copy(self) -> SegmentState:
        return replace(self)


def normalize_target(raw: str) -> str:
    """Normalize a host literal for internal use without any name resolution.

    IPv6 literals are canonicalized via ``ipaddress``; IPv4 literals are passed
    through ``ipaddress`` too; anything else is treated as a hostname and
    lower-cased. Resolution happens only in the real backend, never here, so the
    planner and the simulation share one representation.
    """
    token = raw.strip()
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        pass
    hostname = token.rstrip(".").lower()
    if not hostname:
        raise ValueError("empty host")
    return hostname


def segment_of(host: str, prefix_len: int = 24) -> str:
    """Return the segment key for ``host``.

    IPv4 addresses are masked to ``prefix_len``; IPv6 to ``max(prefix_len, 64)``
    so that a /24 setting does not lump unrelated IPv6 space together; hostnames
    collapse into a single ``"dns"`` segment because the scheduler cannot reason
    about their topology without resolving them.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "dns"
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
    else:
        net = ipaddress.ip_network(f"{addr}/{max(prefix_len, 64)}", strict=False)
    return str(net)


def unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))
