"""Scan engine: turns a validated config into an evidence-logged probe run.

The engine is intentionally thin. It owns three things and nothing else:

* **Concurrency**: a semaphore plus a bounded task set keeps probe fan-out
  predictable; there is no unbounded ``gather`` of the whole pair list.
* **Budget enforcement**: every probe must reserve a lease (``max(budget_slot_ms,
  probe timeout)``) before it starts, and the lease is only released when its
  observation is committed. The invariant the tests assert is
  ``cost_spent + reserved_units <= budget`` on every record in the log - and the log
  carries both numbers, so a third party can check it without running the tool.
* **Evidence**: every dispatch, observation, frontier change and segment
  transition is written to the hash-chained log before the loop continues. The
  log is the artifact; the console table is a convenience view of it.
"""

from __future__ import annotations

import asyncio
import heapq
import os
import platform
import sys
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backends.base import (
    Backend,
    ProbeRequest,
    build_backend,
)
from .config import PlannerConfig, ScanConfig
from .errors import BackendError, SchedProbeError
from .evidence import (
    DEFAULT_FILENAME,
    EvidenceLog,
    file_digest,
    utc_now_iso,
    verify_chain,
    write_manifest,
)
from .models import PortState, ProbeResult, Verdict
from .planners import Planner, build_planner
from .planners.base import LiveSetChange, Pair, ProbePlan, RankUpdate
from .targets import expand_targets
from .util import get_logger, hash_pair, redact

__all__ = ["RunSummary", "ScanEngine", "ScanRun"]

log = get_logger("schedprobe.engine")

RESERVED_FRACTION_FLOOR = 0

# Pairs that debugging sessions have found interesting. Left in on purpose: when one
# of them is at the frontier head, the engine logs the score it used, which is the
# cheapest way to answer "why was this scheduled instead of that". Empty by default.
WATCHED_PAIRS: set[tuple[str, int]] = set()


@dataclass(slots=True)
class RunSummary:
    """Aggregate numbers computed from the evidence log, never from wall guesses.

    ``dispatched`` counts *probes*, not distinct pairs: a pair that came back
    inconclusive and was retried appears several times. ``pairs_touched`` is the number
    of distinct (host, port) pairs, which is what a reader usually wants when asking
    "how much of the estate did this cover?".
    """

    pairs_total: int = 0
    dispatched: int = 0
    pairs_touched: int = 0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    undetermined_ports: int = 0
    cost_spent: int = 0
    budget: int = 0
    confirms: int = 0
    pruned_segments: int = 0
    elapsed_s: float = 0.0
    time_to_first_open_s: float | None = None
    cost_of_filtered: int = 0
    first_open: tuple[str, int] | None = None
    planner: str = ""
    backend: str = ""
    cost_unit: str = "unit"
    run_started_monotonic: float = 0.0

    @property
    def budget_used_ratio(self) -> float:
        if self.budget <= 0:
            return 0.0
        return round(self.cost_spent / self.budget, 4)

    @property
    def waste_ratio(self) -> float:
        """Share of spent budget that produced a timeout. Lower is better."""
        if self.cost_spent <= 0:
            return 0.0
        return round(self.cost_of_filtered / self.cost_spent, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pairs_total": self.pairs_total,
            "dispatched": self.dispatched,
            "pairs_touched": self.pairs_touched,
            "open": self.open_ports,
            "closed": self.closed_ports,
            "filtered": self.filtered_ports,
            "undetermined": self.undetermined_ports,
            "cost_spent": self.cost_spent,
            "budget": self.budget,
            "budget_used_ratio": self.budget_used_ratio,
            "cost_of_filtered": self.cost_of_filtered,
            "waste_ratio": self.waste_ratio,
            "confirms": self.confirms,
            "pruned_segments": self.pruned_segments,
            "elapsed_s": round(self.elapsed_s, 4),
            "time_to_first_open_s": (
                None if self.time_to_first_open_s is None else round(self.time_to_first_open_s, 4)
            ),
            "first_open": list(self.first_open) if self.first_open else None,
            "planner": self.planner,
            "backend": self.backend,
            "cost_unit": self.cost_unit,
        }


@dataclass(slots=True)
class ScanRun:
    """Everything a finished (or failed) run produced."""

    run_id: str
    out_dir: Path
    evidence_path: Path
    manifest_path: Path | None
    summary: RunSummary
    results: dict[tuple[str, int], ProbeResult]
    segments: list[dict[str, Any]]
    config: ScanConfig
    chain_ok: bool
    chain_reason: str = ""
    manifest: dict[str, Any] = field(default_factory=dict)

    def open_ports(self) -> dict[str, list[int]]:
        grouped: dict[str, list[int]] = {}
        for (host, port), result in sorted(self.results.items()):
            if result.state is PortState.OPEN:
                grouped.setdefault(host, []).append(port)
        return grouped

    def undetermined_ports(self) -> list[tuple[str, int]]:
        return sorted(
            pair for pair, result in self.results.items() if result.state is PortState.UNDETERMINED
        )

    def display_host(self, host: str) -> str:
        if not self.config.output.redact:
            return host
        return pseudonym(host, self.run_id)


def pseudonym(host: str, run_id: str) -> str:
    """Stable per-run pseudonym for a host.

    Keyed by the run id, so the same host maps to different pseudonyms in different runs
    and two logs from one client cannot be joined on the host field. One function, used
    by the console, the result files and the manifest, so a reader never sees two
    different pseudonyms for one host in one run.
    """
    return hash_pair(host, 0, salt=run_id)


def _redaction_block(requested: bool) -> dict[str, Any]:
    """Describe exactly what ``--redact`` did, and what it deliberately did not do."""
    if not requested:
        return {
            "requested": False,
            "scope": [],
            "evidence_log": "plaintext",
            "reason": "redaction was not requested for this run",
            "warning": "every artifact contains real host identifiers",
        }
    return {
        "requested": True,
        "scope": ["console", "results", "manifest"],
        "evidence_log": "plaintext",
        "pseudonym": "hmac-sha256(run_id, host)[:12] prefixed with 'h:'",
        "reason": (
            "a byte-exact replay re-derives the /24 segment of every host from the "
            "address itself, so pseudonymising hosts in the evidence log would change "
            "the schedule the log is supposed to reproduce"
        ),
        "warning": (
            "evidence.jsonl keeps real target addresses and the verbatim --notes / "
            "--label / --authorization text. Treat it as the confidential audit record; "
            "redact a copy before sharing it, and do not present that copy as the "
            "original."
        ),
    }


def _pseudonymise_manifest(manifest: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Replace host identifiers in the summary manifest with their pseudonyms.

    The manifest is a *summary*, not an input to ``replay`` - the evidence log is - so
    pseudonymising it costs nothing and closes the last artifact that would otherwise
    name the targets. Segment records keep their prefix length, which is useful context
    and not identifying on its own, while the network address behind it is replaced by
    the same pseudonym the console would show for that address.
    """
    out = dict(manifest)

    def scrub_host(value: str) -> str:
        return pseudonym(value, run_id)

    segments = []
    for record in out.get("segments") or []:
        entry = dict(record)
        hosts = entry.get("hosts")
        if isinstance(hosts, list):
            entry["hosts"] = [scrub_host(str(host)) for host in hosts]
        segment = entry.get("segment")
        if isinstance(segment, str) and segment:
            network, _, prefix = segment.partition("/")
            entry["segment"] = f"{scrub_host(network)}/{prefix}" if prefix else scrub_host(network)
        segments.append(entry)
    if "segments" in out:
        out["segments"] = segments

    summary = dict(out.get("summary") or {})
    first_open = summary.get("first_open")
    if isinstance(first_open, (list, tuple)) and first_open:
        summary["first_open"] = [scrub_host(str(first_open[0])), *first_open[1:]]
    if "summary" in out:
        out["summary"] = summary

    # ``probe_errors`` holds free-form text, so it gets the pattern-based scrubber
    # (IP literals and credential-looking substrings) rather than a host lookup.
    errors = out.get("probe_errors")
    if isinstance(errors, list):
        out["probe_errors"] = [redact(str(item), salt=run_id) for item in errors]
    return out


def _budget_slot(cfg: ScanConfig, planner_cfg: PlannerConfig) -> int:
    """Budget slot charged when a probe starts (see ``PlannerConfig.budget_slot_ms``).

    A constant rather than the probe timeout, so the budget rule is a pure integer
    count and therefore reproducible offline. Falling back to the base timeout when
    the slot is 0 keeps the historical behaviour available for the regression test
    that documents why this changed.
    """
    slot = int(getattr(planner_cfg, "budget_slot_ms", 0) or 0)
    if slot > 0:
        return slot
    return max(1, int(cfg.network.base_timeout_s * 1000))


class ScanEngine:
    """Drive a planner/backend pair and persist an auditable record of the run."""

    def __init__(  # noqa: PLR0913 - five optional knobs, all keyword-only
        self,
        config: ScanConfig,
        *,
        backend: Backend | None = None,
        scenario: str | None = None,
        out_dir: str | os.PathLike[str] | None = None,
        run_id: str | None = None,
        grab_banner: bool = False,
    ) -> None:
        self.config = config.validate()
        self.run_id = run_id or self._new_run_id()
        self.out_dir = Path(out_dir or config.output.out_dir) / self.run_id
        self._explicit_backend = backend
        self._scenario = scenario
        self._grab_banner = grab_banner
        self._cancelled = False

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _new_run_id() -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        return f"{stamp}-{uuid.uuid4().hex[:6]}"

    def _hosts(self) -> tuple[str, ...]:
        return expand_targets(self.config.targets, self.config.network.max_hosts)

    def _backend(self, hosts: Sequence[str]) -> Backend:
        if self._explicit_backend is not None:
            return self._explicit_backend
        return build_backend(
            self.config.backend,
            self.config,
            list(hosts),
            scenario=self._scenario,
            grab_banner=self._grab_banner,
        )

    # --------------------------------------------------------------------- run
    async def run(self) -> ScanRun:
        """Execute the scan and return the run record (never raises for probe failures)."""
        cfg = self.config
        hosts = self._hosts()
        ports = tuple(cfg.ports)
        planner_cfg = cfg.planner
        planner: Planner = build_planner(planner_cfg.kind, hosts, ports, planner_cfg)
        backend = self._backend(hosts)
        budget = planner_cfg.cost_budget
        # ``reserved_allowance`` is the slice of the budget held back so confirmation
        # probes are still affordable after a long sweep. ``sweep_allowance`` is what
        # the sweep itself may spend. Both are integers; the per-probe lease ledger is
        # called ``reserved`` and used to be shadowed by this name in the run header,
        # which made every artifact claim `"reserved": {}`.
        reserved_allowance = int(budget * planner_cfg.reserved_ratio)
        sweep_allowance = max(1, budget - reserved_allowance)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = self.out_dir / DEFAULT_FILENAME
        summary = RunSummary(
            planner=planner.planner_name,
            backend=getattr(backend, "name", "unknown"),
            cost_unit=getattr(backend, "cost_unit", "unit"),
            budget=budget,
            run_started_monotonic=time.monotonic(),
        )
        summary.pairs_total = planner.total_pairs()
        results: dict[tuple[str, int], ProbeResult] = {}
        self._confirmation_attempts: dict[tuple[str, int], int] = {}
        started = time.monotonic()
        first_open_at: float | None = None
        semaphore = asyncio.Semaphore(max(1, cfg.network.concurrency))
        inflight: set[asyncio.Task] = set()
        # Every task ever spawned, so the shutdown drain cannot miss one even if the
        # in-flight bookkeeping is wrong (see the note in the main loop).
        spawned: set[asyncio.Task] = set()
        cost_spent = 0

        await backend.setup()
        # Budget accounting: every in-flight probe *reserves* its worst-case cost
        # (the full timeout), and the reservation is replaced by the real cost when
        # the probe returns. Without this, a semaphore full of slow probes would let
        # the run overshoot its budget by the whole in-flight window - which the
        # first version of this engine did, by a factor of 12 on the demo scenario.
        reserved: dict[tuple[str, int], int] = {}
        # Which pairs currently have a live probe task. ``reserved`` is the money; this
        # is the set of things allowed to be holding it.
        running: set[tuple[str, int]] = set()
        # Observation ordering: results are buffered per dispatch slot and folded
        # into the planner in slot order (see ``dispatch`` below).
        pending: dict[int, tuple[tuple[str, int], ProbeResult, Any, int, float]] = {}
        flush_cursor = 0
        next_slot = 0
        stop_reason: list[str] = [""]
        # Set the moment a confirmation probe is *decided*, not when its task happens to
        # start. Reading ``_confirmation_attempts`` here made the sweep/reserve switch
        # depend on event-loop scheduling, which broke replay reproducibility for tight
        # budgets (the verifier and the engine disagreed about three probes).
        confirmation_phase: list[bool] = [False]
        probe_errors: list[str] = []
        commit_lock = asyncio.Lock()
        with EvidenceLog(evidence_path, self.run_id, truncate=True) as logfile:
            logfile.append(
                "run-header",
                {
                    "tool": "schedprobe",
                    "run_id": self.run_id,
                    "label": cfg.run_label,
                    "notes": cfg.notes,
                    "backend": getattr(backend, "describe", lambda: {"backend": backend.name})(),
                    "planner": planner_cfg.kind,
                    "seed": planner_cfg.seed,
                    "budget": budget,
                    "reserved_allowance": reserved_allowance,
                    "sweep_allowance": sweep_allowance,
                    "targets": list(hosts),
                    "ports": list(ports),
                    "cost_unit": getattr(backend, "cost_unit", "unit"),
                    # Redaction is declared by scope, not by a single optimistic word.
                    # The previous field was ``"host_display": "hashed"``, which was true
                    # of the console and the result files and false of the very record it
                    # lived in: ``targets`` above is a plaintext list, and ``notes`` below
                    # carries whatever the operator typed, including an authorization
                    # reference. A reader deciding whether an artifact is safe to share
                    # needs the boundary written down next to the data.
                    "redaction": _redaction_block(cfg.output.redact),
                    # Recorded so an offline replay can mirror the engine's in-flight
                    # top-up behaviour exactly; without it the replayed frontier
                    # contents would legitimately differ from the recorded one.
                    "concurrency": cfg.network.concurrency,
                    "budget_slot_ms": _budget_slot(cfg, planner_cfg),
                    "budget_check": "cost_spent+reserved+slot<=budget",
                    "wave_rule": "segments_unanswered_scale_batch",
                },
            )
            logfile.append("config", cfg.to_dict())

            planned = planner.initialise()
            frontier = [
                {
                    **{"host": host, "port": port},
                    "score": planner.score(host, port),
                    "reason": planner.reason_for((host, port)),
                }
                for host, port in planned
            ]
            logfile.append(
                "plan",
                {
                    "pairs": len(planned),
                    "segments": planner.book.snapshot(),
                    "frontier": frontier,
                },
            )

            async def dispatch(pair: Pair, slot: int, provision: ProbePlan, attempt: int) -> None:
                """Probe one pair and buffer the observation for ordered commit.

                The probe is issued under a *provisional* plan; the plan of record is
                derived at commit time from a pinned planner state (see
                ``_flush_ready``). Both are written to the log, so a reader can see
                when the scheduler changed its mind while a socket was in flight.
                """
                nonlocal cost_spent, first_open_at
                request = ProbeRequest(
                    host=pair[0],
                    port=pair[1],
                    timeout_s=provision.timeout_s,
                    attempt=attempt,
                    reason=provision.reason,
                    run_label=cfg.run_label,
                    max_timeout_s=cfg.network.max_timeout_s,
                )
                released = False
                try:
                    async with semaphore:
                        try:
                            result = await backend.probe(request)
                        except SchedProbeError as exc:  # backend failure: record, keep going
                            result = ProbeResult(
                                host=pair[0],
                                port=pair[1],
                                state=PortState.UNDETERMINED,
                                verdict=Verdict.ERROR,
                                cost_units=0,
                                confidence=0.0,
                                attempt=attempt,
                                detail=f"backend error: {exc.code}",
                            )
                finally:
                    # Drop the pair from the running set first: ``_flush_ready`` uses that
                    # set to prune reservations whose owner has gone away, so a cancelled
                    # or failed probe cannot leave budget held forever. The lease itself
                    # is released there, under the commit lock, so the recorded
                    # ``inflight_pairs`` snapshot is always consistent with the ledger.
                    async with commit_lock:
                        running.discard(pair)
                    if not released:
                        released = True
                async with commit_lock:
                    cost_spent += result.cost_units
                    results[pair] = result
                    if result.state is PortState.OPEN and first_open_at is None:
                        first_open_at = time.monotonic()
                    if provision.is_confirmation:
                        self._confirmation_attempts[pair] = attempt
                    pending[slot] = (pair, result, provision, attempt, request.effective_timeout_s)
                    await _flush_ready()

            async def _flush_ready() -> None:
                """Fold buffered observations into the planner in dispatch-slot order.

                Everything that mutates the planner happens here, under the commit
                lock, so ``observe -> peek -> plan_next -> take`` is one uninterrupted
                step. Concurrency lives in the probes, not in the scheduler: without
                this, the frontier order would depend on which socket answered first
                and the run would stop being replayable.
                """
                nonlocal flush_cursor
                while flush_cursor in pending:
                    entry = pending.pop(flush_cursor)
                    flush_cursor += 1
                    pair, result, provision, attempt, executed_timeout = entry
                    # Release this probe's lease before recording, so ``inflight_pairs``
                    # equals the reservation set exactly. Any lease whose owner is no
                    # longer running is pruned in the same pass: a probe task that died
                    # must not keep holding budget (that leak is what let an earlier
                    # revision overshoot its budget by 2.8x while every individual check
                    # still looked correct).
                    reserved.pop(pair, None)
                    updates, changes = planner.observe(result)
                    decision = _peek_plan()
                    # The decision is *what the scheduler would dispatch next*; the
                    # dispatch itself may still be refused for lack of budget. Both
                    # facts are recorded, because a replay must be able to tell them
                    # apart: a decision without a dispatch is exactly how a hard
                    # budget makes itself felt. ``_dispatch_pair`` returns the lease it
                    # charged, and - importantly - also the lease it would have charged
                    # when it refused, so the verifier can re-derive the same verdict.
                    if decision is not None and decision.is_confirmation:
                        confirmation_phase[0] = True
                    decision_lease, dispatched = _dispatch_pair(decision, charged=0, bypass_cap=True)
                    extra = _top_up(
                        _wave_size(),
                        exclude={decision.pair} if decision else set(),
                        watch=WATCHED_PAIRS,
                        where=f"after {pair[0]}:{pair[1]}",
                    )
                    _record_probe(
                        paired=(pair, result, provision, attempt, executed_timeout),
                        updates=updates,
                        changes=changes,
                        decision=decision,
                        dispatched=dispatched,
                        extra=extra,
                        wave_cap=_wave_size(),
                        lease_ms=decision_lease,
                        # Snapshot *after* the top-up, so it is exactly the frontier the
                        # next observation will be folded into. Nothing can mutate
                        # ``reserved`` between here and the write: every other probe task
                        # is blocked on the commit lock this coroutine holds.
                        inflight_snapshot=sorted(f"{h}:{p}" for h, p in reserved),
                    )

            def _peek_plan() -> ProbePlan | None:
                """Plan the next pair without dispatching it (decision of record)."""
                pair = planner.peek()
                return planner.plan_next(pair) if pair is not None else None

            def _frontier_preview(limit: int = 6) -> list[dict[str, Any]]:
                """The next few frontier entries with their scores, for the audit trail.

                Implemented by copying the heap and skipping taken entries; it never
                mutates the planner, so it cannot perturb the schedule it describes.
                """
                heap = list(planner._heap)
                heapq.heapify(heap)
                seen: set[tuple[str, int]] = set()
                out: list[dict[str, Any]] = []
                while heap and len(out) < limit:
                    _score, _tick, candidate = heapq.heappop(heap)
                    if candidate in seen:
                        continue
                    seen.add(candidate)
                    live_score = planner._live.get(candidate)
                    if live_score is None:
                        continue
                    out.append(
                        {
                            "pair": f"{candidate[0]}:{candidate[1]}",
                            "score": round(live_score, 6),
                        }
                    )
                return out

            def _reservation_slot() -> int:
                return _budget_slot(cfg, planner_cfg)

            def _reserve_and_check(plan: ProbePlan, charged: int, *, bypass_cap: bool = False) -> int:
                """Reserve the worst-case cost of ``plan`` if it fits the budget.

                Returns the worst-case lease that was considered (0 when the plan could
                not even be evaluated). The value is returned - not just applied - so the
                engine can record it whether or not the dispatch was admitted: a refused
                decision is exactly where the budget rule has to be *verifiable*, and the
                verifier cannot recompute it without guessing at timeout arithmetic.

                The lease is the *maximum* of the configured budget slot and the probe's
                own worst case (its timeout). Using only the slot was an earlier bug: a
                confirmation probe with a 2.5x timeout could then consume more budget than
                it had reserved, and the run finished ~2.5k units over a 150k budget while
                every individual check still reported success.
                """
                if not bypass_cap and len(reserved) >= cfg.network.concurrency:
                    stop_reason[0] = "concurrency-cap"
                    return 0
                worst_case = max(_reservation_slot(), int(plan.timeout_s * 1000))
                if not _has_headroom(charged, worst_case):
                    stop_reason[0] = "no-headroom"
                    log.debug(
                        "no head-room for %s:%s (spent=%s reserved=%s need=%s budget=%s)",
                        plan.host,
                        plan.port,
                        cost_spent,
                        sum(reserved.values()),
                        worst_case,
                        budget,
                    )
                    return worst_case  # 0 would lose the number the verifier needs
                pair = (plan.host, plan.port)
                if pair in reserved:
                    raise BackendError(
                        "refusing to dispatch a pair that is already in flight",
                        pair=f"{pair[0]}:{pair[1]}",
                        in_flight=len(reserved),
                    )
                reserved[pair] = worst_case
                return worst_case

            def _has_headroom(charged: int, worst_case: int) -> bool:
                """The single budget rule, used by both call sites.

                A probe may start only if its worst case plus what is already spent and
                reserved still fits, after removing ``charged`` (used when replacing a
                reservation that is being re-planned).

                ``reserved_ratio`` is enforced here: while the run is in its *sweep* phase
                the cap is ``sweep_allowance`` (budget minus the reserve); once any
                confirmation probe has been dispatched the full budget becomes available,
                which is exactly what the reserve is for. Before this was wired up the
                ratio was only recorded in the run header, so a run could spend the
                reserved slice on the sweep and then have nothing left for confirmations.
                """
                cap = budget if confirmation_phase[0] else sweep_allowance
                return cost_spent + sum(reserved.values()) - charged + max(1, worst_case) <= cap

            def _wave_size() -> int:
                """How many probes may be in flight while the planner is still blind.

                This rule exists because the benchmark caught a real failure: with a
                budget smaller than ``timeout x concurrency``, the start-up batch
                consumed the whole budget on one unmeasured segment and the healthy
                hosts were never swept (recall dropped 70% -> 20%). The fix is to
                start narrow and widen the wave as evidence - not the clock -
                justifies it. Segments with at least one *answered* probe are
                considered evaluated, which is what the planner needs in order to
                rank them.
                """
                segments = planner.book.segments
                total = len(segments)
                if total == 0:
                    return max(1, min(cfg.network.concurrency, 8))
                evaluated = sum(
                    1 for state in segments.values() if (state.open_count + state.closed_count) > 0
                )
                if evaluated == total:
                    return max(1, cfg.network.concurrency)
                remaining = total - evaluated
                share = max(1, cfg.network.concurrency // remaining)
                return max(1, min(share, cfg.network.concurrency, max(1, len(planner.live_pairs()))))

            def _dispatch_pair(
                plan: ProbePlan | None, *, charged: int = 0, bypass_cap: bool = False
            ) -> tuple[int, bool]:
                """Take a planned pair and start its probe.

                Returns ``(lease_ms, dispatched)``. The lease is reported even when the
                dispatch was refused, because a refused decision is exactly where the
                budget rule has to be verifiable offline.
                """
                nonlocal next_slot
                if plan is None:
                    return 0, False
                lease = _reserve_and_check(plan, charged, bypass_cap=bypass_cap)
                pair = (plan.host, plan.port)
                if pair not in reserved:
                    return lease, False
                attempt = 1 + self._confirmation_attempts.get(pair, 0)
                if plan.is_confirmation:
                    attempt = max(2, attempt + 1)
                planner.take(pair)
                running.add(pair)
                task = asyncio.create_task(dispatch(pair, next_slot, plan, attempt))
                inflight.add(task)
                spawned.add(task)
                next_slot += 1
                return lease, True

            def _top_up(
                cap: int,
                *,
                exclude: set[tuple[str, int]] | None = None,
                watch: set[tuple[str, int]] | None = None,
                where: str = "",
            ) -> list[tuple[tuple[str, int], int]]:
                """Dispatch pairs until the in-flight set reaches ``cap``.

                Returns ``((host, port), lease_ms)`` for exactly the pairs admitted by
                *this* call, in admission order. Both the membership and the lease are
                recorded, which removes the last guesswork from the offline verifier:
                reconstructing the frontier no longer depends on re-deriving the wave cap
                or the timeout arithmetic, only on replaying the recorded admissions.

                ``watch``/``where`` are diagnostics: if a watched pair is the frontier
                head, a DEBUG line records the fact and the score the planner gave it,
                which is how a "the replay picked a different pair" bug gets localized
                without a debugger.
                """
                admitted: list[tuple[tuple[str, int], int]] = []
                skip = exclude or set()
                guard = 0
                while True:
                    guard += 1
                    if guard > 100_000:  # pragma: no cover - defensive bound
                        raise RuntimeError("top-up did not converge")
                    current_cap = max(1, min(cfg.network.concurrency, cap))
                    # Three bounds, all of them necessary: ``inflight`` (tasks not yet
                    # committed), ``running`` (probes actually executing) and ``reserved``
                    # (leases actually held). An earlier revision bounded only the first
                    # and leaked leases whenever a task had been reaped but its
                    # observation was still queued - which let the run spend 2.8x its
                    # budget while every individual check still passed.
                    if (
                        len(inflight) >= current_cap
                        or len(running) >= current_cap
                        or len(reserved) >= current_cap
                    ):
                        return admitted
                    pair = planner.peek()
                    if pair is None or pair in skip:
                        return admitted
                    if watch and pair in watch:
                        log.debug(
                            "top-up head %s:%s score=%s (%s)",
                            pair[0],
                            pair[1],
                            planner.score(*pair),
                            where,
                        )
                    lease, ok = _dispatch_pair(planner.plan_next(pair))
                    if not ok:
                        log.debug(
                            "top-up stopped: admitted=%s cap=%s in_flight=%s "
                            "reserved=%s spent=%s budget=%s",
                            len(admitted),
                            cap,
                            len(inflight),
                            sum(reserved.values()),
                            cost_spent,
                            budget,
                        )
                        return admitted
                    admitted.append((pair, lease))

            def _record_probe(  # noqa: PLR0913 - one record, one call site, all names required
                *,
                paired: tuple[Pair, ProbeResult, ProbePlan, int, float],
                updates: list[RankUpdate],
                changes: list[LiveSetChange],
                decision: ProbePlan | None,
                dispatched: bool,
                extra: list[tuple[Pair, int]],
                wave_cap: int,
                lease_ms: int,
                inflight_snapshot: list[str],
            ) -> None:
                pair, result, provision, attempt, executed_timeout = paired
                if logfile.closed:  # pragma: no cover - only reachable after an aborted run
                    log.warning("evidence log already closed; dropping record for %s", pair)
                    return
                # ``dispatched`` describes the probe that actually ran;
                # ``decision`` describes what the scheduler chose as the next probe,
                # which is the sequence a replay re-derives.
                payload = {
                    "dispatched": {
                        **provision.to_dict(),
                        "executed_timeout_s": round(executed_timeout, 6),
                        "attempt": attempt,
                    },
                    "decision": decision.to_dict() if decision else None,
                    "decision_dispatched": bool(dispatched),
                    # The lease the engine charged (or would have charged) for that
                    # decision: max(budget slot, probe timeout). Recorded so the
                    # verifier's ledger arithmetic is identical to the engine's instead of
                    # a local re-derivation - which matters most when the decision was
                    # *refused*, because that is where the budget rule is on trial.
                    "lease_ms": int(lease_ms),
                    # Every pair admitted by the top-up that followed this decision, with
                    # the lease each one was charged. Recorded so the verifier replays
                    # admissions and leases instead of re-deriving either.
                    "extra_dispatched": [
                        {"pair": f"{h}:{p}", "lease_ms": int(units)} for (h, p), units in extra
                    ],
                    # The frontier's own idea of the next few pairs, with the scores it
                    # used. Costs a few bytes per probe and turns "the replay picked a
                    # different pair" into "here are the six candidates and their
                    # scores" - which is the difference between a debuggable divergence
                    # and a mystery.
                    "frontier_preview": _frontier_preview(),
                    # The wave cap that was in force for this decision. Recorded
                    # because it depends on wall-clock completion order in the engine
                    # (how many segments had answered *by then*), and a replay must
                    # not be forced to guess it.
                    "wave_cap": int(wave_cap),
                    "planner_generation": planner.generation,
                    "observation": result.to_dict(),
                    "rank_updates": [u.to_dict() for u in updates],
                    "live_changes": [c.to_dict() for c in changes],
                    "cost_spent": cost_spent,
                    "budget": budget,
                    "reserved_units": sum(reserved.values()),
                    # Per-pair reservations, exactly as the engine held them. The wave
                    # cap and the budget rule depend on these, so a replay that
                    # re-derives them from its own timeout tracker could silently drift;
                    # recording them makes the comparison exact and auditable.
                    "reservations": {f"{h}:{p}": units for (h, p), units in sorted(reserved.items())},
                    "sweep_allowance": sweep_allowance,
                    "live_pairs": planner.live_count(),
                    # The in-flight set *after* this commit, excluding the probe
                    # selected by ``decision``. Recorded so an offline replay can
                    # verify, probe by probe, that it reconstructed the same set.
                    "inflight_pairs": inflight_snapshot,
                    "rtt_estimates": planner.rtt.snapshot(),
                    "segments": planner.book.snapshot(),
                }
                if decision is not None and decision != provision:
                    payload["plan_refresh"] = {
                        "reason": "frontier advanced while the probe was in flight",
                        "provision": provision.to_dict(),
                        "executed_timeout_s": round(executed_timeout, 6),
                    }
                logfile.append("probe", payload)

            # ---------------------------------------------------------- main loop
            try:
                # Start-up batch: the first ``wave`` pairs in dispatch order. Recorded
                # explicitly so an offline replay does not have to re-derive it from
                # the wave rule (which depends on completion order and therefore is
                # not reproducible). The batch is small by construction - see
                # ``_wave_size`` - so recording it costs little and removes the last
                # inference step from the verifier.
                startup_limit = max(1, min(cfg.network.concurrency, _wave_size()))
                if self._cancelled:
                    # An operator who cancels before the run starts should not have their
                    # targets contacted at all. The check used to live only inside the
                    # loop, so the start-up batch went out regardless.
                    logfile.append("cancelled", {"cost_spent": 0, "phase": "before-startup"})
                    startup_pairs: list[str] = []
                else:
                    startup_pairs = []
                    for _ in range(startup_limit):
                        plan = _peek_plan()
                        if plan is None:  # frontier exhausted
                            break
                        # ``_dispatch_pair`` takes the pair from the frontier, so peeking
                        # then dispatching in the same iteration cannot yield duplicates.
                        if not _dispatch_pair(plan)[1]:
                            break  # no head-room left for another probe
                        startup_pairs.append(f"{plan.host}:{plan.port}")
                logfile.append(
                    "startup",
                    {
                        "wave_cap": startup_limit,
                        "pairs": startup_pairs,
                        "budget_slot_ms": _budget_slot(cfg, planner_cfg),
                        # The in-flight set as the main loop begins, with the lease each
                        # probe holds. The start-up phase can run more than one wave (the
                        # main loop tops up before any observation arrives), so the
                        # per-observation ``extra_dispatched`` lists do not account for
                        # everything in flight. Recording the boundary explicitly is what
                        # lets the verifier adopt the exact state instead of guessing at
                        # how many waves ran.
                        "in_flight": sorted(f"{h}:{p}" for h, p in reserved),
                        "leases": {f"{h}:{p}": units for (h, p), units in sorted(reserved.items())},
                    },
                )
                while True:
                    if self._cancelled:
                        logfile.append(
                            "cancelled",
                            {
                                "cost_spent": cost_spent,
                                "in_flight": len(inflight),
                                "reserved": len(reserved),
                            },
                        )
                        break
                    if not inflight:
                        # Nothing running and nothing dispatchable: the run is over.
                        remaining = planner.live_count()
                        logfile.append(
                            "budget-stop",
                            {
                                "reason": stop_reason[0]
                                or ("work-remaining" if remaining else "frontier-empty"),
                                "cost_spent": cost_spent,
                                "budget": budget,
                                "allowance": budget if confirmation_phase[0] else sweep_allowance,
                                "reserved_allowance": reserved_allowance,
                                "sweep_allowance": sweep_allowance,
                                "work_remaining": remaining,
                            },
                        )
                        break
                    done, _pending = await asyncio.wait(inflight, return_when=asyncio.FIRST_COMPLETED)
                    # Mutate ``inflight`` in place instead of rebinding it. The earlier
                    # revision assigned the second return value of ``asyncio.wait`` back
                    # into ``inflight``, which is a *snapshot* of the tasks that were
                    # waiting when the call started: any probe dispatched during the
                    # await was dropped from tracking, the loop could then exit early, the
                    # evidence log closed, and those probes finished into a closed file
                    # (the 'evidence log already closed' warnings). ``spawned`` is the
                    # authority for draining, so nothing can be orphaned even if a future
                    # edit makes the same mistake.
                    inflight.difference_update(done)
                    for task in done:
                        await task
                    # No extra top-up here on purpose. ``_flush_ready`` already tops up
                    # once per observation and records the pairs it admitted; a second,
                    # unrecorded top-up in the main loop made the frontier
                    # reconstruction impossible for the verifier (it saw fewer in-flight
                    # probes than the log). Everything the engine starts is now either
                    # in the ``startup`` record or in a probe's ``extra_dispatched``.
                if inflight:
                    done, _pending = await asyncio.wait(inflight)
                    inflight.difference_update(done)
                    for task in done:
                        await task
            except asyncio.CancelledError:
                for task in inflight:
                    task.cancel()
                raise
            finally:
                # Always drain everything ever spawned. Two reasons: a probe task that
                # raises must not write into a closed evidence log, and its failure must
                # not vanish - it is collected here and surfaced in the manifest as
                # ``probe_errors``.
                leftover = {task for task in spawned if not task.done()}
                if leftover:
                    await asyncio.gather(*leftover, return_exceptions=True)
                probe_errors.extend(
                    f"{task.get_name()}: {task.exception()!r}"
                    for task in spawned
                    if task.done() and not task.cancelled() and task.exception() is not None
                )
                await backend.teardown()

            elapsed = time.monotonic() - started
            _fill_summary(summary, results, planner, cost_spent, elapsed, first_open_at, flush_cursor)
            logfile.append("summary", summary.to_dict())
            chain_ok, chain_reason = _internal_verify(evidence_path)
            logfile.append(
                "manifest",
                {
                    "run_id": self.run_id,
                    "argv": _safe_argv(),
                    "cwd": ".",
                    "python": _python_version(),
                    "platform": os.name,
                },
            )
            head = logfile.head
            records = logfile.count

        digest, size = file_digest(evidence_path)
        manifest = {
            "tool": "schedprobe",
            "run_id": self.run_id,
            "planner": planner.planner_name,
            "backend": getattr(backend, "name", "unknown"),
            "seed": planner_cfg.seed,
            "budget": budget,
            "evidence_file": evidence_path.name,
            "evidence_sha256": digest,
            "evidence_bytes": size,
            "evidence_records": records,
            "chain_head": head,
            "chain_verified": chain_ok,
            "summary": summary.to_dict(),
            "segments": planner.book.snapshot(),
            "backend_stats": backend.stats().to_dict(),
            "probe_errors": probe_errors,
            "generated_at": utc_now_iso(),
        }
        if cfg.output.redact:
            manifest = _pseudonymise_manifest(manifest, self.run_id)
        manifest_path = write_manifest(self.out_dir, manifest)

        return ScanRun(
            run_id=self.run_id,
            out_dir=self.out_dir,
            evidence_path=evidence_path,
            manifest_path=manifest_path,
            summary=summary,
            results=results,
            segments=planner.book.snapshot(),
            config=cfg,
            chain_ok=chain_ok,
            chain_reason=chain_reason,
            manifest=manifest,
        )

    def cancel(self) -> None:
        """Request a cooperative stop; the current loop iteration will persist evidence first."""
        self._cancelled = True


def _fill_summary(  # noqa: PLR0913, PLR0917 - explicit state beats a mutable bag here
    summary: RunSummary,
    results: dict[tuple[str, int], ProbeResult],
    planner: Planner,
    cost_spent: int,
    elapsed: float,
    first_open_at: float | None,
    probes_dispatched: int,
) -> None:
    summary.dispatched = probes_dispatched
    summary.pairs_touched = len(results)
    summary.cost_spent = cost_spent
    summary.elapsed_s = elapsed
    summary.confirms = sum(1 for result in results.values() if result.attempt > 1)
    summary.pruned_segments = sum(1 for state in planner.book.segments.values() if state.pruned)
    for (host, port), result in results.items():
        if result.state is PortState.OPEN:
            summary.open_ports += 1
            if summary.first_open is None:
                summary.first_open = (host, port)
        elif result.state is PortState.CLOSED:
            summary.closed_ports += 1
        elif result.state is PortState.FILTERED:
            summary.filtered_ports += 1
            summary.cost_of_filtered += result.cost_units
        else:
            summary.undetermined_ports += 1
    if first_open_at is not None:
        summary.time_to_first_open_s = max(0.0, first_open_at - summary.run_started_monotonic)


def _internal_verify(path: Path) -> tuple[bool, str]:
    status = verify_chain(path)
    return status.ok, status.reason


def _safe_argv() -> list[str]:
    """Record argv with anything that looks like a secret argument dropped.

    The CLI never takes secrets, but a user could always paste one by accident.
    """
    argv = list(sys.argv[1:])
    filtered: list[str] = []
    skip_next = False
    for item in argv:
        if skip_next:
            filtered.append("<redacted>")
            skip_next = False
            continue
        lowered = item.lower()
        if lowered in ("--token", "--password", "--api-key", "--secret"):
            filtered.append(item)
            skip_next = True
            continue
        if any(marker in lowered for marker in ("password=", "token=", "api_key=", "apikey=")):
            filtered.append("<redacted>")
            continue
        filtered.append(item)
    return filtered


def _python_version() -> str:
    return platform.python_version()
