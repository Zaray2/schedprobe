"""Frontier simulation shared by the engine and the replay verifier.

The hard-won lesson behind this module: **a scheduler is only reproducible if the
set of probes it considers "in flight" is reproducible too.** The first drafts of
this project recorded a decision per probe and expected the replay to infer the
queue from it; it could not, because the engine dispatches several probes
concurrently and finishes them in whatever order the world allows.

So the rules are now explicit data:

* every decision names one pair and records whether it was actually dispatched;
* every record carries the set of in-flight pairs and their per-pair reservations
  as the engine held them;
* the budget rule that decides whether a new pair may be dispatched is one
  function (:meth:`CostLedger.may_dispatch`) evaluated against two ledgers - cost
  actually spent, and worst-case cost reserved by probes still running.

:class:`Frontier` reimplements the engine's bookkeeping over that data, so a
divergence is a *verifiable* statement about the scheduler rather than a guess.
It is deliberately decoupled from ``ScanEngine`` so it can be unit-tested with
hand-written records.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import EvidenceError
from .planners.base import Planner

__all__ = ["CostLedger", "Frontier", "Pair"]

Pair = tuple[str, int]


def pair_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def _decode_extra(item: Any) -> tuple[str, int | None]:
    """Read one ``extra_dispatched`` entry in either supported shape.

    Current logs write ``{"pair": "host:port", "lease_ms": 600}``; older logs wrote a
    bare ``"host:port"``. Accepting both keeps older evidence logs verifiable, which
    matters because the whole point of the format is that a report can be re-checked
    later.
    """
    if isinstance(item, Mapping):
        key = str(item.get("pair", ""))
        lease = item.get("lease_ms")
        return key, int(lease) if isinstance(lease, (int, float)) else None
    return str(item), None


@dataclass(slots=True)
class CostLedger:
    """Two ledgers: what was spent, and what is currently reserved.

    Both are needed because they answer different questions. ``spent`` is what the
    budget has already consumed; ``reserved`` is the worst case still owed to
    probes that are in flight. Dispatch is allowed only when
    ``spent + reserved + worst_case <= budget``, which is what makes the budget a
    hard cap rather than a suggestion.
    """

    budget: int
    # Cap in force *during the sweep phase*: ``budget`` minus the reserved slice, so the
    # reserve is still there when a confirmation probe needs it. ``None`` means the full
    # budget is already available (either the caller wired no reserve, or the run has
    # entered its confirmation phase). The engine and the verifier must agree on which
    # cap is active at every step, which is why it lives in the ledger rather than being
    # recomputed at each call site.
    sweep_cap: int | None = None
    spent: int = 0
    reserved: dict[Pair, int] = field(default_factory=dict)

    @property
    def reserved_total(self) -> int:
        return sum(self.reserved.values())

    @property
    def committed(self) -> int:
        return self.spent + self.reserved_total

    @property
    def effective_cap(self) -> int:
        return self.budget if self.sweep_cap is None else min(self.sweep_cap, self.budget)

    def may_dispatch(self, worst_case: int) -> bool:
        return self.committed + max(1, int(worst_case)) <= self.effective_cap

    def reserve(self, pair: Pair, worst_case: int) -> bool:
        units = max(1, int(worst_case))
        if not self.may_dispatch(units):
            return False
        self.reserved[pair] = units
        return True

    def release(self, pair: Pair) -> int:
        return self.reserved.pop(pair, 0)

    def settle(self, pair: Pair, actual_cost: int) -> None:
        """Release a finished probe's reservation and charge its real cost."""
        self.release(pair)
        self.spent += max(0, int(actual_cost))

    def inflight_snapshot(self) -> list[str]:
        return sorted(pair_key(host, port) for host, port in self.reserved)

    def reservation_map(self) -> dict[str, int]:
        return {pair_key(host, port): units for (host, port), units in sorted(self.reserved.items())}

    def restored(self, snapshot: Iterable[str], reservations: Mapping[str, int]) -> None:
        """Rebuild the ledger from a recorded snapshot (used by the verifier)."""
        self.reserved.clear()
        for key in snapshot:
            host, _, port = key.rpartition(":")
            pair = (host, int(port))
            self.reserved[pair] = int(reservations.get(key, 0)) or 1000


class Frontier:
    """Replays the engine's frontier bookkeeping over recorded decisions.

    Usage pattern::

        frontier = Frontier(planner, ledger)
        frontier.start(capacity, wave_size_at_start)
        for record in records:
            frontier.consume(observation, dispatched_pair)
            ok = frontier.admit(decision, dispatched_flag, wave_cap)

    Every method is side-effect free apart from mutating this object, so a caller
    can inspect :attr:`in_flight` and :attr:`ledger` between steps and report a
    precise divergence.
    """

    def __init__(self, planner: Planner, ledger: CostLedger) -> None:
        self.planner = planner
        self.ledger = ledger
        self.in_flight: set[Pair] = set()

    # ------------------------------------------------------------------ start-up
    def start(self, cap: int) -> list[Pair]:
        """Fill the in-flight set up to ``cap`` (already adjusted to the wave rule).

        Used only when a log predates the explicit ``startup`` record; new logs call
        :meth:`start_with` with the batch the engine actually chose.
        """
        taken: list[Pair] = []
        while len(self.in_flight) < max(1, cap):
            pair = self.planner.peek()
            if pair is None:
                break
            worst_case = self._worst_case(pair)
            if not self.ledger.reserve(pair, worst_case):
                break
            self.planner.take(pair)
            self.in_flight.add(pair)
            taken.append(pair)
        return taken

    def adopt(self, pairs: Iterable[Pair], leases: Mapping[str, int]) -> None:
        """Adopt a recorded in-flight set verbatim, with the leases it held.

        This is the strongest form of start-up reconstruction: the log states exactly
        which probes were running and how much budget each was holding, so the verifier
        does not have to reproduce the engine's wave arithmetic at all. It is used when
        the ``startup`` record carries a snapshot (all logs written by this version).
        """
        for pair in pairs:
            key = pair_key(*pair)
            lease = int(leases.get(key, 0)) or self._worst_case(pair)
            if not self.ledger.reserve(pair, lease):
                raise EvidenceError(
                    "recorded start-up state does not fit the budget",
                    pair=key,
                    spent=self.ledger.spent,
                    reserved=self.ledger.reserved_total,
                    budget=self.ledger.budget,
                )
            self.planner.take(pair)
            self.in_flight.add(pair)

    def start_with(self, pairs: Iterable[Pair]) -> list[Pair]:
        """Adopt an explicitly recorded start-up batch.

        Raises :class:`EvidenceError` if the recorded batch cannot be funded, which
        would mean the log and the ledger disagree about the budget rule.
        """
        taken: list[Pair] = []
        for pair in pairs:
            if not self.ledger.reserve(pair, self._worst_case(pair)):
                raise EvidenceError(
                    "recorded start-up batch does not fit the budget",
                    pair=f"{pair[0]}:{pair[1]}",
                    spent=self.ledger.spent,
                    reserved=self.ledger.reserved_total,
                    budget=self.ledger.budget,
                )
            self.planner.take(pair)
            self.in_flight.add(pair)
            taken.append(pair)
        return taken

    # ---------------------------------------------------------------- per record
    def consume(self, pair: Pair, actual_cost: int) -> None:
        """Close out a finished probe: charge its cost and drop it from the queue."""
        self.ledger.settle(pair, actual_cost)
        self.in_flight.discard(pair)
        self.planner.take(pair)

    def admit(
        self,
        pair: Pair,
        *,
        dispatched: bool,
        extra: Iterable[Any] = (),
        worst_case_ms: int | None = None,
    ) -> tuple[bool, list[Pair]]:
        """Admit the decision of record, then the recorded top-up batch.

        Returns ``(decision_dispatched, admitted_extra)``. ``dispatched`` is the flag
        the engine recorded; if the ledger refuses where the engine accepted (or the
        reverse), the caller reports it - that is a genuine budget-rule divergence.

        ``extra`` entries are either ``{"pair": "h:p", "lease_ms": n}`` mappings (current
        format) or bare ``"h:p"`` strings (logs written before the lease was recorded).
        Replaying the recorded admissions - with their leases - is what makes the
        reconstruction exact; re-deriving either from local timeout estimates is how
        the earlier revisions of this verifier produced phantom divergences.

        ``worst_case_ms`` is the lease the engine charged for this decision.
        """
        took = self.ledger.reserve(pair, worst_case_ms or self._worst_case(pair))
        if took != dispatched:
            # The engine's verdict and the ledger's differ: that is a real divergence in
            # the budget rule, not a comparison detail, so it is raised rather than
            # silently reconciled. The caller turns this into a replay failure.
            raise EvidenceError(
                "budget-rule divergence: engine and ledger disagree on whether the "
                "decision could be dispatched",
                pair=pair_key(*pair),
                engine_dispatched=dispatched,
                ledger_allows=took,
                spent=self.ledger.spent,
                reserved=self.ledger.reserved_total,
                budget=self.ledger.budget,
            )
        if took:
            self.planner.take(pair)
            self.in_flight.add(pair)
        extra_pairs: list[Pair] = []
        for item in extra:
            key, lease = _decode_extra(item)
            host, _, port_text = key.rpartition(":")
            extra_pair = (host, int(port_text))
            if not self.ledger.reserve(extra_pair, lease or self._worst_case(extra_pair)):
                # The engine admitted it, so the ledger must agree. Report upstream by
                # leaving the pair out; the in-flight snapshot check will flag it.
                break
            self.planner.take(extra_pair)
            self.in_flight.add(extra_pair)
            extra_pairs.append(extra_pair)
        return took, extra_pairs

    def fill_to(self, cap: int) -> list[Pair]:
        """Top up to ``cap`` from the replayed frontier, using recorded leases absent.

        Only used to reproduce the engine's extra start-up waves. It stops at the first
        pair the ledger refuses, mirroring the engine's own behaviour.
        """
        admitted: list[Pair] = []
        while len(self.in_flight) < max(1, cap):
            pair = self.planner.peek()
            if pair is None:
                break
            if not self.ledger.reserve(pair, self._worst_case(pair)):
                break
            self.planner.take(pair)
            self.in_flight.add(pair)
            admitted.append(pair)
        return admitted

    # ------------------------------------------------------------------- helpers
    def _worst_case(self, pair: Pair) -> int:
        """Worst-case cost of a probe, in the backend's cost unit.

        With a configured ``budget_slot_ms`` this is a constant: the budget is then a
        pure count of probe slots, independent of the RTT estimate. Otherwise it falls
        back to the probe timeout, which is what the first implementation did - and
        which the replay could not reproduce, because the timeout depends on a
        per-host estimator that the engine advances in completion order.
        """
        slot = getattr(self.planner.config, "budget_slot_ms", 0)
        if slot and slot > 0:
            return int(slot)
        return max(1, int(self.planner.timeout_for(pair) * 1000))

    def snapshot(self) -> list[str]:
        return self.ledger.inflight_snapshot()

    def describe(self) -> dict[str, Any]:
        return {
            "in_flight": len(self.in_flight),
            "reserved": self.ledger.reserved_total,
            "spent": self.ledger.spent,
            "budget": self.ledger.budget,
        }
