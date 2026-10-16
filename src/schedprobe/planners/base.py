"""Planner interface plus the small shared helpers every scheduler needs.

A planner answers exactly two questions and nothing else:

1. **Which (host, port) pairs are in scope?** - :meth:`Planner.plan`
2. **In what order, and is this pair still worth a probe?** - :meth:`Planner.rank`

Everything the planner knows about the world arrives through
:meth:`Planner.observe`. Planners must be pure functions of
``(config, seed, observation sequence)``: no wall-clock reads, no module-level
randomness, no filesystem access. That restriction is what makes ``replay`` a
meaningful operation instead of a re-scan.
"""

from __future__ import annotations

import heapq
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..models import ProbeResult, SegmentState, Verdict, segment_of
from ..targets import segment_map
from ..util import get_logger

if TYPE_CHECKING:
    from ..config import PlannerConfig

log = get_logger("schedprobe.planner")

__all__ = [
    "LiveSetChange",
    "Planner",
    "ProbePlan",
    "RankUpdate",
    "RttTracker",
    "SegmentBook",
    "pair_key",
]

Pair = tuple[str, int]


def pair_key(host: str, port: int) -> Pair:
    return (host, port)


@dataclass(frozen=True, slots=True)
class RankUpdate:
    """A changed priority for an already-planned pair."""

    host: str
    port: int
    score: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "score": round(self.score, 6),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class LiveSetChange:
    """A pair that must leave (or re-enter) the frontier."""

    host: str
    port: int
    added: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "added": self.added,
            "reason": self.reason,
        }


class SegmentBook:
    """Shared bookkeeping of per-segment state; used by all planners.

    Keeping this in one place means the adaptive planner and the fixed planner
    disagree about *policy* only, never about *accounting* - which matters when
    the benchmark compares their budgets.
    """

    def __init__(self, hosts: Sequence[str], prefix_len: int) -> None:
        self.prefix_len = prefix_len
        self._segments: dict[str, SegmentState] = {}
        for segment, members in segment_map(hosts, prefix_len).items():
            self._segments[segment] = SegmentState(segment=segment, hosts=members)

    def register_ports(self, ports: Sequence[int]) -> None:
        for state in self._segments.values():
            state.ports = tuple(state.ports) + tuple(ports)

    @property
    def segments(self) -> dict[str, SegmentState]:
        return self._segments

    def of(self, host: str) -> SegmentState:
        return self._segments[segment_of(host, self.prefix_len)]

    def observe(self, result: ProbeResult) -> SegmentState:
        state = self.of(result.host)
        state.planned += 1
        state.observe(result)
        return state

    def health(self, segment: str, timeout_penalty: float = 1.0) -> float:
        return self._segments[segment].health_score(timeout_penalty)

    def total_cost(self) -> int:
        return sum(state.cost_spent for state in self._segments.values())

    def prune(self, segment: str, reason: str) -> SegmentState:
        state = self._segments[segment]
        state.pruned = True
        state.prune_reason = reason
        return state

    def snapshot(self) -> list[dict[str, Any]]:
        return [state.as_dict() for _, state in sorted(self._segments.items())]


@dataclass(frozen=True, slots=True)
class ProbePlan:
    """A dispatch decision: which pair, why, and - importantly - with what timeout.

    The timeout lives here rather than in the engine because it is a *decision*,
    and decisions have to be replayable. ``timeout_reason`` is a stable token that
    the report can aggregate.
    """

    host: str
    port: int
    timeout_s: float
    reason: str
    priority: float
    is_confirmation: bool = False

    @property
    def pair(self) -> Pair:
        return (self.host, self.port)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "timeout_s": round(self.timeout_s, 6),
            "reason": self.reason,
            "priority": round(self.priority, 6),
            "is_confirmation": self.is_confirmation,
        }


class RttTracker:
    """Per-host round-trip estimate used to derive probe timeouts.

    This is the second half of the project's scheduling story. A fixed timeout is
    wrong in both directions: too small and a slow-but-open port is reported as
    ``filtered`` (a false negative); too large and every genuinely filtered port
    burns the whole budget. The tracker keeps an exponentially weighted estimate
    per host and widens it when a probe actually times out, because a timeout
    means "this may be filtered *or* this host is slower than I assumed".

    Bounds come from ``NetworkConfig.min_timeout_s`` / ``max_timeout_s`` and the
    estimator is deterministic: no clocks, only arithmetic on observed costs.
    """

    def __init__(
        self,
        base_timeout_s: float,
        minimum_s: float,
        maximum_s: float,
        alpha: float = 0.4,
    ) -> None:
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        self.base = float(base_timeout_s)
        self.minimum = float(minimum_s)
        self.maximum = float(maximum_s)
        self.alpha = float(alpha)
        self._rtt: dict[str, float] = {}
        self._current: dict[str, float] = {}

    def current(self, host: str) -> float:
        return self._current.get(host, self.base)

    def rtt(self, host: str) -> float | None:
        return self._rtt.get(host)

    def observe(self, host: str, *, responded: bool, cost_s: float) -> None:
        """Update the estimate for ``host``.

        ``cost_s`` is the observed round trip expressed in seconds. The fake
        backend reports milliseconds as its abstract unit, so callers convert.
        """
        if responded:
            prior = self._rtt.get(host, cost_s)
            estimate = self.alpha * cost_s + (1.0 - self.alpha) * prior
            self._rtt[host] = estimate
            target = estimate * 3.0
            current = self._current.get(host, self.base)
            # Shrink faster than we grow: a healthy host should not keep paying for
            # one early timeout.
            shrunk = current * 0.95 + target * 0.05
            self._current[host] = self._clamp(min(current, target) if current > target else shrunk)
        else:
            current = self._current.get(host, self.base)
            self._current[host] = self._clamp(current * 1.6)

    def pin(self, host: str, value: float) -> None:
        """Record a restored estimate.

        Exposed for callers that reconstruct planner state from a log instead of
        replaying observations; the shipped verifier re-feeds observations and therefore
        does not need it, but embedding this class in another tool does.
        """
        self._current[host] = self._clamp(value)

    def _clamp(self, value: float) -> float:
        return round(min(self.maximum, max(self.minimum, value)), 6)

    def snapshot(self) -> dict[str, float]:
        return {host: round(value, 6) for host, value in sorted(self._current.items())}


class Planner:
    """Abstract base class. Subclasses must be deterministic given their seed."""

    name = "base"

    def __init__(self, hosts: Sequence[str], ports: Sequence[int], config: PlannerConfig) -> None:
        self.hosts = tuple(hosts)
        self.ports = tuple(ports)
        self.config = config
        self.book = SegmentBook(self.hosts, getattr(config, "prefix_len", 24))
        self.book.register_ports(self.ports)
        self._live: dict[Pair, float] = {}
        self._reasons: dict[Pair, str] = {}
        # Per-pair priority overrides (confirmations). ``score`` consults this, so the
        # heap key, ``_live`` and ``score`` can never disagree about the same pair.
        self._priorities: dict[Pair, float] = {}
        self._confirmations: dict[Pair, int] = {}
        self._heap: list[tuple[float, int, Pair]] = []
        self._tick = 0
        self._dispatched: set[Pair] = set()
        # Monotonic count of folded observations. The engine stamps each dispatch
        # with the generation it planned under and re-plans if the generation moved
        # before the result was committed, so a plan is always derived from a
        # reproducible planner state rather than from whatever the frontier happened
        # to look like when a socket first answered.
        self.generation = 0
        self._heap_dirty = False
        self.rtt = self._make_tracker()

    def _make_tracker(self) -> RttTracker:
        network = getattr(self.config, "network", None)
        base = float(getattr(network, "base_timeout_s", 0.6))
        minimum = float(getattr(network, "min_timeout_s", 0.15))
        maximum = float(getattr(network, "max_timeout_s", 3.0))
        return RttTracker(base, minimum, maximum)

    # ------------------------------------------------------------------ contract
    @property
    def planner_name(self) -> str:
        return self.name

    def total_pairs(self) -> int:
        return len(self.hosts) * len(self.ports)

    def plan(self) -> list[Pair]:
        """Return the full in-scope pair list in deterministic *initial* order."""
        raise NotImplementedError

    def initial_reason(self) -> str:
        return "sweep"

    def score(self, host: str, port: int) -> float:
        """Lower score wins. Must be a pure function of current planner state."""
        override = self._priorities.get((host, port))
        if override is not None:
            return override
        return self.base_score(host, port)

    def base_score(self, host: str, port: int) -> float:
        """Segment/policy score, ignoring any per-pair override."""
        raise NotImplementedError

    # -------------------------------------------------------------- engine hooks
    def initialise(self) -> list[Pair]:
        """Populate the frontier and return the pairs in dispatch order."""
        pairs = self.plan()
        for host, port in pairs:
            self._live[(host, port)] = self.score(host, port)
            self._reasons[(host, port)] = self.initial_reason()
        self.reheap()
        return list(pairs)

    def mark_heap_dirty(self) -> None:
        """Mark the heap as needing a rebuild before the next ``peek``.

        Called whenever scores change without a heap entry being pushed for them -
        for example when one observation rescales a whole segment. Without this the
        heap keeps ordering pairs by their *old* scores while ``_live`` holds the new
        ones, and ``peek`` can return a pair that is not the minimum. That failure is
        silent in normal output and only shows up as an unreproducible schedule, which
        is exactly what the replay verifier caught here.
        """
        self._heap_dirty = True

    def reheap(self) -> None:
        """Rebuild the heap from the live scores.

        ``_live`` is the authority; the heap is only an index over it. Rebuilding is
        O(n) and is used whenever the *membership* of the frontier changes in bulk.
        """
        self._heap = []
        self._heap_dirty = False
        for pair, score in self._live.items():
            self._tick += 1
            heapq.heappush(self._heap, (score, self._tick, pair))

    def _check_heap_invariant(self, returned: Pair) -> None:
        """Verify that ``peek`` returned the live minimum, not merely a heap minimum.

        Cheap to state, O(n) to check, and therefore off by default (``--verify-heap``).
        It exists because a heap that mis-orders the frontier produces a schedule that
        cannot be reproduced - and that failure mode is invisible in the output until
        someone tries to replay the run.
        """
        true_min = min(self._live.items(), key=lambda item: item[1])
        if true_min[0] != returned:
            log.warning(
                "frontier order violation: peek returned %s score=%s but the live minimum is "
                "%s score=%s (live=%s, heap=%s)",
                returned,
                self._live.get(returned),
                true_min[0],
                true_min[1],
                len(self._live),
                len(self._heap),
            )

    def peek(self) -> Pair | None:
        """Return the next pair to dispatch, without consuming it.

        The frontier is a lazy heap: when a segment's health changes, priorities
        change but the heap still holds the old keys. Stale entries are detected by
        comparing the stored score with the live score and re-pushed with the fresh
        key, so ``peek`` always answers with what ``plan_next`` would dispatch next.

        Invariant this establishes: after ``peek`` returns ``p``, no *live* pair has
        a score below ``score(p)``. The engine and the verifier both rely on it.
        """
        rebuilt = False
        if self._heap_dirty:
            self.reheap()
            rebuilt = True
        while self._heap:
            score, _, pair = self._heap[0]
            current = self._live.get(pair)
            if current is None:
                heapq.heappop(self._heap)
                continue
            if current != score:
                heapq.heappop(self._heap)
                # A stale key means the heap no longer orders the frontier. Rather
                # than re-pushing this one entry and hoping, rebuild once from
                # ``_live``: correctness here is worth an O(n) rebuild, because a
                # heap that mis-orders the frontier silently produces a schedule
                # nobody - including the replay verifier - can reproduce.
                if not rebuilt:
                    self.reheap()
                    rebuilt = True
                continue
            if getattr(self.config, "verify_heap", False):
                self._check_heap_invariant(pair)
            return pair
        return None

    def take(self, pair: Pair) -> None:
        """Mark a pair as dispatched so it never comes back from the frontier."""
        self._dispatched.add(pair)
        self._live.pop(pair, None)
        self._priorities.pop(pair, None)
        self._reasons.pop(pair, None)

    def pop(self) -> Pair | None:
        pair = self.peek()
        if pair is None:
            return None
        self.take(pair)
        return pair

    def reason_for(self, pair: Pair) -> str:
        return self._reasons.get(pair, self.initial_reason())

    def timeout_for(self, pair: Pair) -> float:
        """Return the timeout this planner wants for ``pair``.

        Default implementation is the configured base timeout; the adaptive
        planner overrides it with the per-host RTT estimate.
        """
        return self.rtt.current(pair[0])

    def plan_next(self, pair: Pair) -> ProbePlan:
        """Bundle the scheduling decision for ``pair`` into one immutable record."""
        is_confirmation = self.reason_for(pair).startswith("confirm")
        return ProbePlan(
            host=pair[0],
            port=pair[1],
            timeout_s=self.timeout_for(pair),
            reason=self.reason_for(pair),
            priority=self._live.get(pair, 0.0),
            is_confirmation=is_confirmation,
        )

    def dispatch_count(self) -> int:
        return len(self._dispatched)

    def live_count(self) -> int:
        return len(self._live)

    def live_pairs(self) -> tuple[Pair, ...]:
        """Pairs still on the frontier, in a deterministic order.

        Exposed for the replay verifier, which needs to compare the replayed
        frontier against the recorded one without guessing the internal order.
        """
        return tuple(sorted(self._live))

    # ------------------------------------------------------------------ observer
    def observe(self, result: ProbeResult) -> tuple[list[RankUpdate], list[LiveSetChange]]:
        """Fold an observation in and report frontier changes.

        Base implementation does nothing; subclasses that replan return deltas so
        the engine can update its frontier in O(changes) instead of O(pairs).
        """
        self.book.observe(result)
        self._note_rtt(result)
        self._confirmations.pop((result.host, result.port), None)
        self.generation += 1
        return [], []

    # --------------------------------------------------------------- helpers
    def _note_rtt(self, result: ProbeResult) -> None:
        """Feed a result into the per-host timeout estimator.

        Only *answered* probes carry timing information. A timeout is fed in as
        'no response' so the estimator widens instead of guessing a round trip.
        """
        responded = result.verdict in (
            Verdict.CONNECTED,
            Verdict.REFUSED,
            Verdict.RESET,
        )
        cost_s = result.cost_units / 1000.0
        if responded:
            # A completed handshake is a true round trip; an RST arrives after the
            # host processed the SYN, which is also a round trip. Both are usable.
            self.rtt.observe(result.host, responded=True, cost_s=max(0.001, cost_s))
        else:
            self.rtt.observe(result.host, responded=False, cost_s=0.0)

    def _confirmation_budget_available(self, pair: Pair) -> bool:
        """True while the pair is still allowed another confirmation attempt.

        The counter is incremented by :meth:`_push_front`, so the total number of
        probes for a pair is ``1 + confirm_min_attempts`` - the initial sweep probe
        plus the bounded retries. Without the bound, a run could spend an unbounded
        share of its budget re-probing the same inconclusive port.
        """
        if pair in getattr(self, "_exhausted", set()):
            return False
        attempts = self._confirmations.get(pair, 0)
        return attempts < getattr(self.config, "confirm_min_attempts", 1)

    def _push_front(self, pair: Pair, priority: float, reason: str) -> RankUpdate:
        """Re-queue a pair ahead of the sweep, on the *same* scale as ``score``.

        The first version wrote a special-cased number straight into ``_live`` while
        ``score`` kept recomputing a segment-derived value, so the heap and ``score``
        disagreed about the same pair: ``peek`` would return a pair that was not the
        minimum, and the replay verifier saw schedule differences that did not exist.
        Overrides now live in ``_priorities`` and ``score`` consults them, so there is
        exactly one definition of a pair's priority.
        """
        self._priorities[pair] = priority
        self._live[pair] = priority
        self._reasons[pair] = reason
        self._confirmations[pair] = self._confirmations.get(pair, 0) + 1
        self._tick += 1
        heapq.heappush(self._heap, (priority, self._tick, pair))
        return RankUpdate(pair[0], pair[1], priority, reason)

    def describe(self) -> dict[str, Any]:
        return {
            "planner": self.planner_name,
            "hosts": len(self.hosts),
            "ports": len(self.ports),
            "pairs": self.total_pairs(),
            "dispatched": self.dispatch_count(),
            "segments": self.book.snapshot(),
        }
