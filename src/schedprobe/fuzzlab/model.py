"""Aggregation and budget accounting for a fuzzing experiment.

Two things live here that the report depends on and that are easy to get wrong:

**The budget is a hard cap checked before the work.** SchedProbe's probe scheduler enforces
this because an overshoot discovered afterwards cannot be undone; a fuzzing campaign has the
same property for a different reason - a campaign that quietly ran 30% longer than its arm's
stated budget produces numbers nobody can compare. The runner stops on the budget and records
whether it hit the cap or finished early.

**Per-arm aggregation over seeds is reported, not collapsed.** A single seed tells you what
one campaign did. The research question is whether a policy is better, which requires the
spread across seeds: an arm that wins on the mean but has a spread wider than the difference
has not shown anything.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from .arms import Arm
from .stats import RunStats


@dataclass(slots=True)
class BudgetLedger:
    """A hard cap on campaign resources, checked before spending.

    ``kind`` is ``"seconds"`` or ``"execs"``. Both are recorded because a wall-clock budget
    and an execution budget answer different questions: the first is what a practitioner can
    afford, the second is how much work was actually done, and a scheduling policy can change
    one without changing the other.
    """

    kind: str
    limit: int
    spent: int = 0

    def remaining(self) -> int:
        return max(0, self.limit - self.spent)

    def exhausted(self) -> bool:
        return self.spent >= self.limit

    def would_exceed(self, units: int) -> bool:
        return self.spent + units > self.limit

    def charge(self, units: int) -> int:
        """Charge ``units`` and return how many were actually granted, capped at the limit."""
        granted = min(units, self.remaining())
        self.spent += granted
        return granted

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "limit": self.limit, "spent": self.spent}


@dataclass(slots=True)
class CampaignResult:
    """One (arm, seed) campaign: the statistics plus the crashes it produced."""

    arm: str
    seed: int
    stats: RunStats
    crashes: list[Any] = field(default_factory=list)
    #: True when the campaign was stopped by its budget rather than by finishing its queue.
    budget_exhausted: bool = True
    #: Which scheduling mechanism the plugin reported using, when it reported one.
    mechanism: str = ""

    @property
    def unique_crashes(self) -> int:
        return len({record.signature for record in self.crashes})

    def to_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "seed": self.seed,
            "stats": self.stats.to_dict(),
            "crashes_total": len(self.crashes),
            "unique_crashes": self.unique_crashes,
            "budget_exhausted": self.budget_exhausted,
            "mechanism": self.mechanism,
            "crash_signatures": sorted({r.signature for r in self.crashes}),
        }


@dataclass(slots=True)
class ArmSummary:
    """Per-arm aggregation across seeds, with the spread kept visible."""

    arm: str
    role: str
    seeds: tuple[int, ...]
    runs: int
    execs_mean: float
    execs_min: int
    execs_max: int
    edges_mean: float
    edges_min: int
    edges_max: int
    coverage_mean: float
    crashes_total: int
    unique_crashes: int
    unique_signatures: tuple[str, ...]

    @property
    def edges_spread(self) -> int:
        return self.edges_max - self.edges_min

    def to_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "role": self.role,
            "seeds": list(self.seeds),
            "runs": self.runs,
            "execs_mean": round(self.execs_mean, 1),
            "execs_min": self.execs_min,
            "execs_max": self.execs_max,
            "edges_mean": round(self.edges_mean, 1),
            "edges_min": self.edges_min,
            "edges_max": self.edges_max,
            "edges_spread": self.edges_spread,
            "coverage_mean": round(self.coverage_mean, 3),
            "crashes_total": self.crashes_total,
            "unique_crashes": self.unique_crashes,
            "unique_signatures": list(self.unique_signatures),
        }


def summarise_arm(arm: Arm, results: list[CampaignResult]) -> ArmSummary:
    """Aggregate one arm's campaigns over its seeds."""
    if not results:
        raise ValueError(f"arm {arm.name!r} has no campaigns to summarise")
    execs = [r.stats.execs_done for r in results]
    edges = [r.stats.edges_found for r in results]
    coverage = [r.stats.coverage_percent for r in results]
    signatures: set[str] = set()
    total_crashes = 0
    for result in results:
        total_crashes += len(result.crashes)
        signatures.update(record.signature for record in result.crashes)
    return ArmSummary(
        arm=arm.name,
        role=arm.role,
        seeds=tuple(r.seed for r in results),
        runs=len(results),
        execs_mean=statistics.fmean(execs),
        execs_min=min(execs),
        execs_max=max(execs),
        edges_mean=statistics.fmean(edges),
        edges_min=min(edges),
        edges_max=max(edges),
        coverage_mean=statistics.fmean(coverage),
        crashes_total=total_crashes,
        unique_crashes=len(signatures),
        unique_signatures=tuple(sorted(signatures)),
    )


@dataclass(slots=True)
class Experiment:
    """A full experiment: one target, one budget, several arms, several seeds."""

    name: str
    target: str
    budget_kind: str
    budget_limit: int
    seeds: tuple[int, ...]
    results: list[CampaignResult] = field(default_factory=list)
    #: Recorded so a reader can tell whether the numbers came from one machine or many.
    environment: dict[str, Any] = field(default_factory=dict)

    def add(self, result: CampaignResult) -> None:
        self.results.append(result)

    def by_arm(self) -> dict[str, list[CampaignResult]]:
        grouped: dict[str, list[CampaignResult]] = {}
        for result in self.results:
            grouped.setdefault(result.arm, []).append(result)
        return grouped

    def summaries(self, arms: tuple[Arm, ...]) -> list[ArmSummary]:
        grouped = self.by_arm()
        return [summarise_arm(arm, grouped[arm.name]) for arm in arms if arm.name in grouped]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target,
            "budget": {"kind": self.budget_kind, "limit": self.budget_limit},
            "seeds": list(self.seeds),
            "environment": self.environment,
            "campaigns": [r.to_dict() for r in self.results],
        }
