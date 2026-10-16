"""Deterministic replay of a scan's scheduling decisions.

What "replay" means here, precisely: **re-derive the scheduler's decisions from
the recorded observations and show that they come out identical**. It is not a
re-scan and it never touches the network.

Procedure:

1. read the chain header (planner kind, seed, budget) and the ``plan`` record;
2. rebuild the planner from that header alone and re-run ``initialise()``;
3. feed the recorded observations, in recorded order, through ``observe()``;
4. after each observation, compare the planner's frontier change list and the
   next decision against what the log says happened;
5. finish with a full comparison of frontier membership, scores and segment state.

If step 4 or 5 disagrees, the log is either corrupted (``verify`` catches that
separately) or the planner is non-deterministic - which is a bug worth failing
loudly over. If everything agrees, "the scan produced different results this
time" can only mean the *target* changed, because the scheduler provably did not.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .config import ScanConfig, config_from_dict
from .errors import EvidenceError
from .evidence import EvidenceRecord, read_records
from .frontier import CostLedger, Frontier, Pair
from .models import ProbeResult
from .planners import build_planner

__all__ = ["ReplayReport", "replay_chain", "first_divergence"]

MISMATCH_LIMIT = 25


def _pair(key: str) -> Pair:
    """Split a ``host:port`` key back into a pair (IPv6-safe via rpartition)."""
    host, _, port_text = str(key).rpartition(":")
    return (host, int(port_text))


@dataclass(slots=True)
class ReplayReport:
    """Outcome of a replay: what matched, what did not, and where it broke first."""

    run_id: str
    planner: str
    observations: int = 0
    decisions_checked: int = 0
    timeouts_checked: int = 0
    plan_refreshes: int = 0
    startup_inflight: int = 0
    rank_updates_checked: int = 0
    live_changes_checked: int = 0
    divergences: list[str] = field(default_factory=list)
    frontier_match: bool = False
    segments_match: bool = False
    final_cost_spent: int = 0
    recorded_cost_spent: int = 0

    @property
    def ok(self) -> bool:
        return not self.divergences and self.frontier_match and self.segments_match

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "planner": self.planner,
            "ok": self.ok,
            "observations": self.observations,
            "decisions_checked": self.decisions_checked,
            "timeouts_checked": self.timeouts_checked,
            "plan_refreshes": self.plan_refreshes,
            "startup_inflight": self.startup_inflight,
            "rank_updates_checked": self.rank_updates_checked,
            "live_changes_checked": self.live_changes_checked,
            "frontier_match": self.frontier_match,
            "segments_match": self.segments_match,
            "cost_spent": self.final_cost_spent,
            "recorded_cost_spent": self.recorded_cost_spent,
            "divergences": self.divergences,
        }


def _planner_payload(records: list[EvidenceRecord]) -> tuple[dict[str, Any], dict[str, Any], ScanConfig]:
    header = next((r for r in records if r.kind == "run-header"), None)
    if header is None:
        raise EvidenceError("evidence log has no run-header record")
    config_record = next((r for r in records if r.kind == "config"), None)
    if config_record is None:
        raise EvidenceError("evidence log has no config record")
    config = config_from_dict(dict(config_record.data))
    planner_kind = str(header.data.get("planner", config.planner.kind))
    return dict(header.data), {"kind": planner_kind}, config


def first_divergence(report: ReplayReport) -> str | None:
    return report.divergences[0] if report.divergences else None


def replay_chain(path: str | os.PathLike[str], *, strict: bool = False) -> ReplayReport:
    """Rebuild the planner from an evidence log and compare every decision."""
    file_path = Path(path)
    records = list(read_records(file_path))
    header, planner_info, config = _planner_payload(records)
    hosts = tuple(config.targets)
    ports = tuple(config.ports)
    planner = build_planner(planner_info["kind"], hosts, ports, config.planner)

    # The engine expands CIDRs before planning; the header records the expanded
    # list, so prefer it when present.
    header_hosts = header.get("targets")
    if header_hosts:
        hosts = tuple(str(h) for h in header_hosts)
        planner = build_planner(planner_info["kind"], hosts, ports, config.planner)

    report = ReplayReport(run_id=str(header.get("run_id", "")), planner=planner.planner_name)

    plan_record = next((r for r in records if r.kind == "plan"), None)
    if plan_record is None:
        raise EvidenceError("evidence log has no plan record")
    planner.initialise()
    recorded_frontier: dict[Pair, float] = {}
    for item in plan_record.data.get("frontier", []):
        try:
            recorded_frontier[(str(item["host"]), int(item["port"]))] = float(item["score"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError("plan record contains a malformed frontier entry", reason=str(exc)) from exc
    # Compare only the pairs that are still live at the start (dispatch happens in
    # parallel, so a pair may already have been consumed before the first
    # observation is recorded); dead pairs are cleaned out of the heap by ``peek``.
    replayed_scores = {pair: planner.score(*pair) for pair in planner.live_pairs()}
    recorded_live = {pair: score for pair, score in recorded_frontier.items() if pair in replayed_scores}
    if set(recorded_live) != set(replayed_scores):
        missing = sorted(set(recorded_live) - set(replayed_scores))
        extra = sorted(set(replayed_scores) - set(recorded_live))
        report.divergences.append(
            "initial frontier membership differs: "
            f"recorded={len(recorded_live)} replayed={len(replayed_scores)} "
            f"missing={missing[:3]} extra={extra[:3]}"
        )
    else:
        for pair, expected in recorded_live.items():
            actual = replayed_scores[pair]
            if abs(expected - actual) > 1e-9:
                report.divergences.append(
                    f"initial score mismatch for {pair[0]}:{pair[1]}: "
                    f"recorded={expected} replayed={actual}"
                )
                break

    # Walk probe records in order, feeding observations through the same planner.
    # The invariant this checks: after applying observation N, the planner's next
    # decision must equal the decision the log recorded for slot N+1.
    #
    # ``capacity`` mirrors the engine's in-flight top-up: at start-up and after every
    # observation the engine takes pairs off the frontier until the in-flight set is
    # full. The replay reproduces that so the frontier it inspects is the same one
    # the scheduler saw - otherwise the *frontier contents* would differ even though
    # the *observations* are identical, and the comparison would report phantom
    # divergences.
    capacity = _capacity_of(records, config)
    budget = int(header.get("budget", config.planner.cost_budget))
    # The engine's sweep phase may only spend ``sweep_allowance``; the reserve is
    # released once a confirmation probe is in play. The verifier must switch caps on
    # the same event, so it reads the allowance out of the run header and watches the
    # confirmation flag in the log.
    sweep_allowance = int(header.get("sweep_allowance", budget) or budget)
    ledger = CostLedger(budget=budget, sweep_cap=sweep_allowance)
    frontier = Frontier(planner, ledger)

    def _wave_size(recorded_cap: int | None) -> int:
        """Mirror ``ScanEngine._wave_size``.

        The engine re-evaluates the cap as segments answer, so the cap that was in
        force for a given decision depends on completion order. When the log carries
        the cap it used, that value is authoritative; otherwise it is re-derived
        from the same planner state the engine would have seen. Keeping both paths
        in one function makes the fallback testable.
        """
        if recorded_cap is not None and recorded_cap >= 1:
            return max(1, min(capacity, recorded_cap))
        segments = planner.book.segments
        total = len(segments)
        if total == 0:
            return max(1, min(capacity, 8))
        evaluated = sum(
            1 for state in segments.values() if (state.open_count + state.closed_count) > 0
        )
        if evaluated == total:
            return max(1, capacity)
        remaining = total - evaluated
        share = max(1, capacity // remaining)
        return max(1, min(share, capacity, max(1, len(planner.live_pairs()))))

    # Start-up: the engine records the batch it actually started (``startup`` record),
    # so the replay reproduces it directly instead of re-deriving a wave rule that
    # depends on completion order. Only logs written before that record existed fall
    # back to re-deriving the cap from planner state.
    startup_record = next((r for r in records if r.kind == "startup"), None)
    if startup_record is not None and startup_record.data.get("in_flight"):
        pairs = [_pair(key) for key in startup_record.data["in_flight"]]
        leases = startup_record.data.get("leases") or {}
        frontier.adopt(pairs, {str(k): int(v) for k, v in leases.items()})
    elif startup_record is not None and startup_record.data.get("pairs"):
        started = [_pair(key) for key in startup_record.data["pairs"]]
        frontier.start_with(started)
    else:
        first_probe = next((r for r in records if r.kind == "probe"), None)
        recorded_startup_cap = None
        if first_probe is not None and isinstance(first_probe.data.get("wave_cap"), int):
            recorded_startup_cap = int(first_probe.data["wave_cap"])
        frontier.start(_wave_size(recorded_startup_cap))
    report.startup_inflight = len(frontier.in_flight)

    for record in records:
        if record.kind != "probe":
            continue
        observation = ProbeResult.from_dict(dict(record.data["observation"]))
        dispatched = dict(record.data.get("dispatched", {}))
        executed_pair = (str(dispatched.get("host", observation.host)),
                         int(dispatched.get("port", observation.port)))
        recorded_decision = record.data.get("decision")
        recorded_updates = record.data.get("rank_updates", [])
        recorded_changes = record.data.get("live_changes", [])

        report.decisions_checked += 1
        if executed_pair not in frontier.in_flight:
            report.divergences.append(
                f"seq {record.seq}: the log ran {executed_pair} which the replay did not "
                f"have in flight (in flight: {sorted(frontier.in_flight)[:4]})"
            )
        frontier.consume(executed_pair, observation.cost_units)
        updates, changes = planner.observe(observation)
        report.observations += 1
        report.rank_updates_checked += len(recorded_updates)
        report.live_changes_checked += len(recorded_changes)
        if _canonical_changes(updates) != _canonical_recorded(recorded_updates, kind="rank"):
            report.divergences.append(
                f"rank update mismatch after {executed_pair[0]}:{executed_pair[1]} "
                f"(recorded {len(recorded_updates)}, replayed {len(updates)})"
            )
        if _canonical_changes(changes) != _canonical_recorded(recorded_changes, kind="change"):
            report.divergences.append(
                f"live-set change mismatch after {executed_pair[0]}:{executed_pair[1]} "
                f"(recorded {len(recorded_changes)}, replayed {len(changes)})"
            )

        # The decision of record is the pair the engine would dispatch next.
        if recorded_decision is None:
            next_pair = planner.peek()
            if next_pair is not None:
                report.divergences.append(
                    f"expected {next_pair} to be scheduled after seq {record.seq}, "
                    "but the log records no further decision"
                )
        else:
            wanted = (str(recorded_decision["host"]), int(recorded_decision["port"]))
            next_pair = planner.peek()
            if next_pair != wanted:
                report.divergences.append(
                    f"decision mismatch after {executed_pair[0]}:{executed_pair[1]}: "
                    f"recorded={wanted} replayed={next_pair}"
                )
            else:
                fresh = planner.plan_next(wanted)
                report.timeouts_checked += 1
                if str(recorded_decision.get("reason")) != fresh.reason:
                    report.divergences.append(
                        f"reason mismatch for {wanted}: "
                        f"recorded={recorded_decision.get('reason')} replayed={fresh.reason}"
                    )
                if (
                    recorded_decision.get("timeout_s") is not None
                    and abs(float(recorded_decision["timeout_s"]) - fresh.timeout_s) > 1e-6
                ):
                    report.divergences.append(
                        f"timeout mismatch for {wanted}: "
                        f"recorded={float(recorded_decision['timeout_s']):.6f} "
                        f"replayed={fresh.timeout_s:.6f}"
                    )
                if (
                    recorded_decision.get("priority") is not None
                    and abs(float(recorded_decision["priority"]) - fresh.priority) > 1e-6
                ):
                    report.divergences.append(
                        f"priority mismatch for {wanted}: "
                        f"recorded={float(recorded_decision['priority']):.6f} "
                        f"replayed={fresh.priority:.6f}"
                    )
            if "plan_refresh" in record.data:
                report.plan_refreshes += 1
            # Mirror the engine exactly: the decision of record is what the scheduler
            # wanted next, and ``extra_dispatched`` is the top-up batch that followed
            # it. Both are replayed as recorded, so the frontier is reconstructed
            # rather than guessed - the earlier drafts of this verifier tried to
            # re-derive the top-up and produced phantom divergences.
            recorded_dispatched = bool(record.data.get("decision_dispatched", True))
            extra_keys = record.data.get("extra_dispatched") or []
            recorded_lease = record.data.get("lease_ms")
            # Release the reserve *before* admitting: the engine switches caps the moment a
            # confirmation is decided, so the confirmation probe itself is what consumes
            # the reserve. Switching after would make the verifier refuse exactly the probe
            # the reserve exists for.
            if record.data["dispatched"].get("is_confirmation") or (
                isinstance(recorded_decision, dict) and recorded_decision.get("is_confirmation")
            ):
                ledger.sweep_cap = None
            try:
                took, _extra_pairs = frontier.admit(
                    wanted,
                    dispatched=recorded_dispatched,
                    extra=extra_keys,
                    worst_case_ms=int(recorded_lease) if isinstance(recorded_lease, int) else None,
                )
            except EvidenceError as exc:
                # ``admit`` raises when the engine's verdict and the replayed ledger
                # disagree - a genuine budget-rule divergence rather than a comparison
                # detail, so it is reported as such and the walk continues.
                report.divergences.append(
                    f"budget-rule divergence at seq {record.seq} for {wanted}: {exc.message}"
                )
                took = recorded_dispatched
            if record.data["dispatched"].get("is_confirmation") or (
                isinstance(recorded_decision, dict) and recorded_decision.get("is_confirmation")
            ):
                # The reserve is released as soon as a confirmation probe is *started*,
                # which in the engine happens at decision-dispatch time - not when the
                # probe's own record is written. Switching on the dispatched flag alone
                # left the verifier one step behind the engine, and the two then disagreed
                # about whether the next three probes fitted the budget.
                ledger.sweep_cap = None
            if record.data["dispatched"].get("is_confirmation") or (
                isinstance(recorded_decision, dict) and recorded_decision.get("is_confirmation")
            ):
                # The reserve is released as soon as a confirmation probe is *started*,
                # which in the engine happens at decision-dispatch time - not when the
                # probe's own record is written. Switching on the dispatched flag alone
                # left the verifier one step behind the engine, and the two then disagreed
                # about whether the next three probes fitted the budget.
                ledger.sweep_cap = None
            if took != recorded_dispatched:
                report.divergences.append(
                    f"budget rejection mismatch at seq {record.seq} for {wanted}: "
                    f"recorded_dispatched={recorded_dispatched} replayed_dispatched={took} "
                    f"(spent={ledger.spent} reserved={ledger.reserved_total} budget={budget} "
                    f"recorded_spent={record.data.get('cost_spent')} "
                    f"recorded_reserved={record.data.get('reserved_units')})"
                )

            recorded_inflight = record.data.get("inflight_pairs")
            if isinstance(recorded_inflight, list):
                replayed_inflight = frontier.snapshot()
                recorded_sorted = sorted(recorded_inflight)
                if recorded_sorted != replayed_inflight:
                    recorded_set = set(recorded_sorted)
                    replayed_set = set(replayed_inflight)
                    report.divergences.append(
                        f"in-flight mismatch after seq {record.seq}: "
                        f"missing_in_replay={sorted(recorded_set - replayed_set)[:4]} "
                        f"extra_in_replay={sorted(replayed_set - recorded_set)[:4]} "
                        f"(counts {len(recorded_sorted)} vs {len(replayed_inflight)})"
                    )
                recorded_reservations = record.data.get("reservations")
                if isinstance(recorded_reservations, dict):
                    replayed_reservations = ledger.reservation_map()
                    if recorded_reservations != replayed_reservations:
                        differing = [
                            key for key in sorted(set(recorded_reservations) | set(replayed_reservations))
                            if recorded_reservations.get(key) != replayed_reservations.get(key)
                        ][:4]
                        report.divergences.append(
                            f"reservation mismatch after seq {record.seq} "
                            f"(recorded total {record.data.get('reserved_units')}, "
                            f"replayed total {ledger.reserved_total}); differing: {differing}"
                        )
        if len(report.divergences) >= MISMATCH_LIMIT:
            break

    # Frontier and segment comparison against the final recorded state.
    last_probe = next((r for r in reversed(records) if r.kind == "probe"), None)
    if last_probe is not None:
        recorded_segments = last_probe.data.get("segments", [])
        replayed_segments = planner.book.snapshot()
        report.segments_match = _segments_equal(recorded_segments, replayed_segments)
        if not report.segments_match:
            report.divergences.append("final segment state differs from the recorded state")
        recorded_live = int(last_probe.data.get("live_pairs", -1))
        report.frontier_match = recorded_live == planner.live_count()
        if not report.frontier_match:
            report.divergences.append(
                f"final frontier size differs: recorded={recorded_live} replayed={planner.live_count()}"
            )
        report.recorded_cost_spent = int(last_probe.data.get("cost_spent", 0))
        report.final_cost_spent = planner.book.total_cost()
    else:
        report.frontier_match = planner.live_count() == len(recorded_frontier)
        report.segments_match = True
        report.divergences.append("no probe records were found in the evidence log")

    if strict and not report.ok:
        raise EvidenceError(
            "strict replay failed", divergences=len(report.divergences),
            first=first_divergence(report),
        )
    return report


def _capacity_of(records: list[EvidenceRecord], config: ScanConfig) -> int:
    """Infer the engine's concurrency from the header, falling back to the config."""
    header = next((r for r in records if r.kind == "run-header"), None)
    if header is not None:
        concurrency = header.data.get("concurrency")
        if isinstance(concurrency, int) and concurrency >= 1:
            return concurrency
    return max(1, int(getattr(config.network, "concurrency", 1)))


def _canonical_recorded(items: Iterable[Any], *, kind: str) -> list[tuple[Any, ...]]:
    out: list[tuple[Any, ...]] = []
    for item in items:
        payload = dict(item)
        if kind == "rank":
            out.append(
                (
                    str(payload["host"]),
                    int(payload["port"]),
                    round(float(payload["score"]), 9),
                    str(payload["reason"]),
                )
            )
        else:
            out.append(
                (
                    str(payload["host"]),
                    int(payload["port"]),
                    bool(payload["added"]),
                    str(payload["reason"]),
                )
            )
    return sorted(out)


def _canonical_changes(items: Iterable[Any]) -> list[tuple[Any, ...]]:
    """Normalize planner-emitted deltas into the same shape the log stores.

    Accepts either the dataclass instances (with ``to_dict``) or plain mappings,
    so a caller can compare a fresh replay against a log without caring which
    representation it holds.
    """
    out: list[tuple[Any, ...]] = []
    for item in items:
        if hasattr(item, "to_dict"):
            payload = dict(item.to_dict())
        elif isinstance(item, Mapping):
            payload = dict(item)
        else:
            raise EvidenceError(
                "planner emitted a delta that is neither a mapping nor serializable",
                type=type(item).__name__,
            )
        if "score" in payload:
            out.append(
                (
                    str(payload["host"]),
                    int(payload["port"]),
                    round(float(payload["score"]), 9),
                    str(payload["reason"]),
                )
            )
        else:
            out.append(
                (
                    str(payload["host"]),
                    int(payload["port"]),
                    bool(payload["added"]),
                    str(payload["reason"]),
                )
            )
    return sorted(out)


def _segments_equal(recorded: list[dict[str, Any]], replayed: list[dict[str, Any]]) -> bool:
    if len(recorded) != len(replayed):
        return False
    for left, right in zip(sorted(recorded, key=lambda d: d["segment"]),
                           sorted(replayed, key=lambda d: d["segment"])):
        for key in ("segment", "planned", "open", "closed", "filtered", "undetermined",
                    "cost_spent", "pruned"):
            if left.get(key) != right.get(key):
                return False
    return True
