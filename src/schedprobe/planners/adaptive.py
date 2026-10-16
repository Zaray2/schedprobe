"""The adaptive, segment-aware budget planner - the project's core contribution.

Policy (each rule is separately testable, see ``tests/test_engine.py`` (``TestAdaptivePolicy``)):

R1 *Segment priority.* A segment's score is derived from its observed health:
   responsive segments outrank unresponsive ones. Rationale: budget spent on a
   segment that keeps timing out buys no information.

R2 *Liveness pruning.* After ``prune_after_consecutive_timeouts`` consecutive
   timeout observations inside one segment (and at least ``prune_min_planned``
   probes), the segment is pruned: its queued pairs are dropped and the *unspent*
   portion of its allocation is handed to the healthy segments. This is the rule
   that produces the benchmark's waste reduction, and the reason pruning needs
   more than one strike is to survive a single unlucky drop.

R3 *Confirmation probes.* A pair whose result is ``undetermined`` or falls below
   ``confidence_threshold`` is pushed back to the front of the frontier with a
   larger timeout (``confirm_timeout_multiplier``), up to
   ``confirm_min_attempts`` extra tries. This trades a little budget for fewer
   false ``filtered`` verdicts - measured as recall/precision in the harness.

R4 *Budget accounting.* ``cost_budget`` is a hard cap on dispatched probe cost.
   ``reserved_ratio`` of it is held back so that confirmation probes are still
   possible after a long sweep; the rest is the sweep allowance.

The planner never reads a clock and never calls ``random`` at decision time -
the seed only shapes the initial order in the ``random`` baseline.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from ..models import PortState, ProbeResult
from .base import LiveSetChange, Pair, Planner, RankUpdate

if TYPE_CHECKING:
    from ..config import PlannerConfig

__all__ = ["AdaptivePlanner", "FixedLongTimeoutPlanner", "FixedOrderPlanner", "RandomOrderPlanner"]


class AdaptivePlanner(Planner):
    """Segment-aware replanning scheduler (R1-R4 above)."""

    name = "adaptive"

    def __init__(self, hosts: Sequence[str], ports: Sequence[int], config: PlannerConfig) -> None:
        super().__init__(hosts, ports, config)
        self._donated = 0
        self._alive = True
        # Last emitted score per pair, used to report only genuine changes.
        self._last_scores: dict[Pair, float] = {}
        # Pairs that have used up their confirmation allowance. Tracked explicitly so a
        # pair that keeps coming back inconclusive cannot restart its retry cycle.
        self._exhausted: set[Pair] = set()

    # -------------------------------------------------------------- initial plan
    def plan(self) -> list[Pair]:
        """Order by segment, then by port: a stable, explainable starting point."""
        pairs: list[Pair] = []
        for segment in sorted(self.book.segments):
            state = self.book.segments[segment]
            for host in state.hosts:
                for port in self.ports:
                    pairs.append((host, port))
        return pairs

    def initial_reason(self) -> str:
        return "sweep-segment-first"

    def base_score(self, host: str, port: int) -> float:
        """Lower wins. Deferred segments sink; dropped segments are gone entirely.

        The port term is a tie-breaker only (a millionth per port), so within a
        segment the sweep still runs in port order without letting that ordering
        outrank the segment decision. ``deferred_penalty`` is larger than the whole
        live score range, so a deferred segment is only probed once everything else
        has been, which is the point of deferring rather than dropping.
        """
        state = self.book.of(host)
        if state.pruned and not state.deferred:
            return float("inf")
        penalty = getattr(self.config, "timeout_penalty", 1.0)
        base = state.health_score(penalty) + port / 1_000_000.0
        if state.deferred:
            base += float(getattr(self.config, "deferred_penalty", 2.0))
        return base

    # ----------------------------------------------------------------- observer
    def observe(self, result: ProbeResult) -> tuple[list[RankUpdate], list[LiveSetChange]]:
        state = self.book.observe(result)
        self._note_rtt(result)
        # The confirmation counter is per-pair and is consumed by ``_push_front``. It
        # must not be cleared on every observation, which is what the first revision did
        # (it popped the counter immediately before asking whether there was budget
        # left, so the answer was always yes and ``confirm_min_attempts`` had no effect).
        # Once a pair exhausts its allowance it is recorded as such so the next
        # inconclusive verdict on the same pair cannot start a new cycle.
        pair = (result.host, result.port)
        if self._confirmations.get(pair, 0) >= getattr(self.config, "confirm_min_attempts", 1):
            self._exhausted.add(pair)
        self._confirmations.pop(pair, None)
        self.generation += 1
        updates: list[RankUpdate] = []
        changes: list[LiveSetChange] = []

        prune_after = getattr(self.config, "prune_after_consecutive_timeouts", 3)
        prune_min = getattr(self.config, "prune_min_planned", 3)
        unresponsive = state.planned > 0 and (state.open_count + state.closed_count) == 0
        if (
            not state.pruned
            and state.planned >= prune_min
            and (state.consecutive_timeouts >= prune_after or unresponsive)
        ):
            reason = (
                f"{state.consecutive_timeouts} consecutive timeouts after {state.planned} probes"
                if state.consecutive_timeouts >= prune_after
                else f"no answered probe in {state.planned} attempts (segment looks dead)"
            )
            mode = getattr(self.config, "prune_mode", "defer")
            self.book.prune(state.segment, reason)
            if mode == "drop":
                for host in state.hosts:
                    for port in self.ports:
                        pair = (host, port)
                        if pair in self._live:
                            self._live.pop(pair, None)
                            changes.append(LiveSetChange(host, port, False, "segment-pruned"))
                self._donated += max(0, state.extra_budget)
                state.extra_budget = 0
            else:
                # Defer instead of drop: the segment's pairs stay on the frontier but
                # sink to the bottom (see ``score``). Measured effect in the benchmark:
                # going from 'drop' to 'defer' recovered 60% -> 100% recall on
                # ``blackhole-segment`` while still cutting cost by ~25% versus fixed.
                state.deferred = True
                self.mark_heap_dirty()

        # Rescore the *whole planned set* in the segments whose health just moved,
        # not just the pairs still on the frontier. The engine dispatches probes
        # concurrently, so a pair may already be in flight when the health changes;
        # scoring only the live pairs would make the number of emitted updates depend
        # on probe timing, which is exactly the kind of hidden coupling that breaks
        # replay. Stale scores for in-flight pairs are harmless - ``take`` drops them.
        baseline = self.plan()
        touched = {state.segment}
        if self._donated:
            alive = max(1, sum(1 for s in self.book.segments.values() if not s.pruned))
            share = self._donated // alive
            if share:
                for segment, other in self.book.segments.items():
                    if not other.pruned and other.extra_budget < share:
                        other.extra_budget = share
                        touched.add(segment)
            self._donated = 0

        for pair in baseline:
            host, port = pair
            if self.book.of(host).segment not in touched:
                continue
            new_score = self.score(host, port)
            if new_score != self._last_scores.get(pair, float("nan")):
                self._last_scores[pair] = new_score
                updates.append(RankUpdate(host, port, new_score, "segment-health-change"))
            if pair in self._live:
                self._live[pair] = new_score
        # Scores changed for a whole segment; the heap can no longer be trusted to
        # order them until it is rebuilt (see ``mark_heap_dirty``).
        if updates:
            self.mark_heap_dirty()

        # R3: confirmation probe for inconclusive results - but only where the result is
        # actually surprising.
        #
        # The benchmark forced this refinement. Confirming *every* timeout doubled the
        # cost of every filtered port, and on `blackhole-segment` that turned a policy
        # that reached 100% recall into one that reached 60%: the retries ate the budget
        # the sweep needed. A timeout in a segment that already drops most of its probes
        # is not surprising, so re-probing it buys nothing; a timeout on a host that has
        # been answering promptly *is* surprising (a dropped packet, a rate limiter, or
        # a genuinely filtered port that deserves a longer window).
        state = self.book.of(result.host)
        answered = state.open_count + state.closed_count
        probeable = state.filtered_count + answered
        drop_ratio = (state.filtered_count / probeable) if probeable else 0.0
        surprising = answered > 0 and drop_ratio < getattr(self.config, "confirm_max_drop_ratio", 0.5)
        if (
            result.state is PortState.UNDETERMINED
            or result.confidence < getattr(self.config, "confidence_threshold", 0.7)
        ) and surprising:
            pair = (result.host, result.port)
            if self._confirmation_budget_available(pair):
                previous = self._live.get(pair)
                entry = self._push_front(pair, self._confirmation_score(result), "confirm-inconclusive")
                # A re-add is both a membership change *and* a priority change; both
                # are reported so the replay verifier can reconstruct the frontier
                # exactly instead of inferring it.
                changes.append(LiveSetChange(result.host, result.port, True, "confirm-inconclusive"))
                if previous is not None and previous != entry.score:
                    updates.append(RankUpdate(result.host, result.port, entry.score, "confirm-rescore"))
            else:
                self._confirmations.setdefault(pair, 0)

        return updates, changes

    # Confirmation priority sits below every sweep score, so a pair waiting to be
    # confirmed is always dispatched before the next sweep probe but still ranks
    # against other confirmations by how weak its evidence was.
    CONFIRMATION_BASE = -1.0

    def _confirmation_score(self, result: ProbeResult) -> float:
        """Confirmations outrank the sweep but stay ordered among themselves.

        A low-confidence verdict is worth confirming precisely *because* it is
        low-confidence, so the score is driven by ``1 - confidence``. Filtered
        verdicts from a short timeout therefore land near the front.

        The score stays below every sweep score (which is <= 0 + a tiny port
        tie-break) by using ``-1.0`` as the base, so a confirmation can never be
        starved behind a long sweep.
        """
        return self.CONFIRMATION_BASE + (1.0 - result.confidence)

    # ------------------------------------------------------------------ reporting
    def confirmation_timeout(self, base_timeout: float) -> float:
        """Timeout to use for a confirmation probe.

        Confirmation probes exist because a single timeout is weak evidence: it could be
        a dropped packet or a genuinely closed port behind a firewall. Widening the
        window on the retry is what separates those two cases, and it is the only place
        the multiplier is applied (``planner.plan_next`` calls this for pairs whose
        reason starts with ``confirm``).
        """
        multiplier = getattr(self.config, "confirm_timeout_multiplier", 2.5)
        ceiling = getattr(self.config, "max_timeout_s", 3.0)
        return min(ceiling, base_timeout * multiplier)

    def timeout_for(self, pair: Pair) -> float:
        """Base timeout, widened for confirmation probes.

        Keeping this override here (rather than in the engine) means the timeout is part
        of the recorded decision and therefore replayable.
        """
        base = super().timeout_for(pair)
        if self.reason_for(pair).startswith("confirm"):
            return self.confirmation_timeout(base)
        return base

    def describe(self) -> dict[str, Any]:
        payload = super().describe()
        payload.update(
            {
                "pruning": {
                    "after_consecutive_timeouts": getattr(
                        self.config, "prune_after_consecutive_timeouts", 3
                    ),
                    "min_planned": getattr(self.config, "prune_min_planned", 3),
                    "pruned_segments": sorted(
                        seg for seg, state in self.book.segments.items() if state.pruned
                    ),
                },
                "confirmation": {
                    "threshold": getattr(self.config, "confidence_threshold", 0.7),
                    "min_attempts": getattr(self.config, "confirm_min_attempts", 2),
                    "timeout_multiplier": getattr(self.config, "confirm_timeout_multiplier", 2.5),
                },
            }
        )
        return payload


class FixedOrderPlanner(Planner):
    """Baseline A: input-order sweep, fixed timeout, no replanning.

    This mirrors the default behaviour of a plain connect scanner and exists so
    the benchmark compares against something a reader recognises.
    """

    name = "fixed"

    def __init__(self, hosts: Sequence[str], ports: Sequence[int], config: PlannerConfig) -> None:
        super().__init__(hosts, ports, config)
        # Precomputed indices: ``list.index`` inside ``score`` is O(n) and ``score`` is
        # called once per pair per observation.
        self._host_index = {host: index for index, host in enumerate(self.hosts)}
        self._port_index = {port: index for index, port in enumerate(self.ports)}

    def plan(self) -> list[Pair]:
        return [(host, port) for host in self.hosts for port in self.ports]

    def initial_reason(self) -> str:
        return "input-order"

    def base_score(self, host: str, port: int) -> float:
        return float(self._host_index[host] * 1_000_000 + self.ports.index(port))

    def observe(self, result: ProbeResult) -> tuple[list[RankUpdate], list[LiveSetChange]]:
        self.book.observe(result)
        return [], []


class RandomOrderPlanner(Planner):
    """Baseline B: shuffled sweep, same fixed timeout.

    Included to separate 'the adaptive policy helps' from 'any non-sorted order
    helps', which is the most obvious alternative explanation for a benchmark win.
    """

    name = "random"

    def __init__(self, hosts: Sequence[str], ports: Sequence[int], config: PlannerConfig) -> None:
        super().__init__(hosts, ports, config)
        self._order: dict[Pair, int] = {}

    def plan(self) -> list[Pair]:
        rng = random.Random(f"schedprobe-random-order:{getattr(self.config, 'seed', 0)}")
        pairs = [(host, port) for host in self.hosts for port in self.ports]
        rng.shuffle(pairs)
        self._order = {pair: index for index, pair in enumerate(pairs)}
        return pairs

    def initial_reason(self) -> str:
        return "shuffled"

    def base_score(self, host: str, port: int) -> float:
        return float(self._order.get((host, port), 0))

    def observe(self, result: ProbeResult) -> tuple[list[RankUpdate], list[LiveSetChange]]:
        self.book.observe(result)
        return [], []


class FixedLongTimeoutPlanner(Planner):
    """Baseline C: input order but one long timeout for every probe.

    Models the 'just raise the timeout until nothing is missed' reflex, and shows
    what it costs when a large share of the target space is filtered.
    """

    name = "fixed-longtimeout"

    def __init__(self, hosts: Sequence[str], ports: Sequence[int], config: PlannerConfig) -> None:
        super().__init__(hosts, ports, config)
        self._host_index = {host: index for index, host in enumerate(self.hosts)}
        self._port_index = {port: index for index, port in enumerate(self.ports)}

    def plan(self) -> list[Pair]:
        return [(host, port) for host in self.hosts for port in self.ports]

    def initial_reason(self) -> str:
        return "input-order-long-timeout"

    def base_score(self, host: str, port: int) -> float:
        return float(self._host_index[host] * 1_000_000 + self.ports.index(port))

    def observe(self, result: ProbeResult) -> tuple[list[RankUpdate], list[LiveSetChange]]:
        self.book.observe(result)
        return [], []
