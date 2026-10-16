"""Reproducible benchmark harness.

The harness answers one question with numbers instead of adjectives:

    Under a fixed probe budget, on the same synthetic network, with the same seed,
    how do four scheduling policies differ in recall, in the share of the budget
    that bought nothing but timeouts, and in the cost needed to reach full recall?

Everything that could make the comparison unfair is pinned:

* the ground truth is fixed by the scenario, so recall/precision are computable;
* the backend is deterministic and order-independent, so the only variable is the
  scheduler;
* all four planners see the same budget and the same confirmation settings;
* results are written with the scenario, seed, budget and tool version so a third
  party can re-run and compare hashes.

This measures the schedulers *inside this project*. It is not a claim about Nmap,
Masscan or any other tool - those were not run here. See
``docs/research/benchmark-results.md`` for the recorded numbers, including the cases
where the adaptive policy *loses*.
"""

from __future__ import annotations

import json
import platform
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .backends.fake import FakeBackend, NetworkScenario, builtin_scenarios
from .config import NetworkConfig, PlannerConfig, ScanConfig
from .engine import ScanEngine
from .errors import ConfigError
from .evidence import read_records
from .models import PortState
from .planners import PLANNER_CLASSES

__all__ = [
    "DEFAULT_PLANNERS",
    "BenchmarkCase",
    "BenchmarkResult",
    "BudgetSweepRow",
    "all_cases",
    "budget_sweep",
    "compare",
    "default_case",
    "environment",
    "run_benchmark",
    "write_results",
]

DEFAULT_PLANNERS: tuple[str, ...] = ("adaptive", "fixed", "random", "fixed-longtimeout")


@dataclass(slots=True)
class BenchmarkCase:
    scenario: str
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    budget: int
    seed: int = 1337
    planners: tuple[str, ...] = DEFAULT_PLANNERS
    prefix_len: int = 24
    base_timeout_s: float = 0.6
    max_timeout_s: float = 3.0
    confirm_min_attempts: int = 1
    confidence_threshold: float = 0.7
    prune_mode: str = "defer"

    def validate(self) -> None:
        if not self.hosts:
            raise ConfigError("benchmark case needs hosts")
        if not self.ports:
            raise ConfigError("benchmark case needs ports")
        if self.budget < 1:
            raise ConfigError("benchmark case needs a positive budget")
        unknown = [p for p in self.planners if p not in PLANNER_CLASSES]
        if unknown:
            raise ConfigError("unknown planner in benchmark case", planners=unknown)
        if self.prune_mode not in ("defer", "drop"):
            raise ConfigError("prune_mode must be defer or drop", value=self.prune_mode)


@dataclass(slots=True)
class BenchmarkResult:
    planner: str
    scenario: str
    seed: int
    budget: int
    dispatched: int
    cost_spent: int
    open_found: int
    open_total: int
    closed_found: int
    closed_total: int
    filtered_found: int
    filtered_total: int
    undetermined: int
    cost_of_filtered: int
    time_to_first_open_cost: int | None
    cost_to_full_recall: int | None
    confirms: int
    pruned_segments: int
    elapsed_s: float
    run_id: str
    evidence: str
    false_open: int = 0

    @property
    def recall(self) -> float:
        return self.open_found / self.open_total if self.open_total else 1.0

    @property
    def precision(self) -> float:
        """Share of open claims that the ground truth agrees with.

        The simulation is lossless about *open* ports (loss can only hide them,
        never invent them), so any disagreement here is a scheduler or engine bug
        rather than network noise - which is what makes it worth asserting on.
        """
        claimed = self.open_found + self.false_open
        return self.open_found / claimed if claimed else 1.0

    @property
    def false_positive_rate(self) -> float:
        total = self.open_found + self.false_open
        return self.false_open / total if total else 0.0

    @property
    def waste_ratio(self) -> float:
        return self.cost_of_filtered / self.cost_spent if self.cost_spent else 0.0

    @property
    def cost_per_open(self) -> float:
        return self.cost_spent / self.open_found if self.open_found else float("inf")

    @property
    def resolved_ratio(self) -> float:
        total = self.open_total + self.closed_total + self.filtered_total
        scanned = self.open_found + self.closed_found + self.filtered_found + self.false_open
        return scanned / total if total else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "planner": self.planner,
            "scenario": self.scenario,
            "seed": self.seed,
            "budget": self.budget,
            "dispatched": self.dispatched,
            "cost_spent": self.cost_spent,
            "open_found": self.open_found,
            "open_total": self.open_total,
            "closed_found": self.closed_found,
            "closed_total": self.closed_total,
            "filtered_found": self.filtered_found,
            "filtered_total": self.filtered_total,
            "undetermined": self.undetermined,
            "false_open": self.false_open,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "resolved_ratio": round(self.resolved_ratio, 4),
            "cost_of_filtered": self.cost_of_filtered,
            "waste_ratio": round(self.waste_ratio, 4),
            "cost_per_open": (None if self.open_found == 0 else round(self.cost_per_open, 2)),
            "time_to_first_open_cost": self.time_to_first_open_cost,
            "cost_to_full_recall": self.cost_to_full_recall,
            "confirms": self.confirms,
            "pruned_segments": self.pruned_segments,
            "elapsed_s": round(self.elapsed_s, 4),
            "run_id": self.run_id,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class BudgetSweepRow:
    """One (scenario, budget, planner) point of the sweep.

    The sweep exists to answer a question a single budget cannot: *at what budget
    does each policy reach full recall?* That number - ``cost_to_full_recall`` - is
    the fairest single comparison available, because it is the point where all
    policies agree on the answer and differ only in what they paid for it.
    """

    scenario: str
    budget: int
    planner: str
    recall: float
    cost_spent: int
    waste_ratio: float
    full_recall: bool
    cost_to_full_recall: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "budget": self.budget,
            "planner": self.planner,
            "recall": round(self.recall, 4),
            "cost_spent": self.cost_spent,
            "waste_ratio": round(self.waste_ratio, 4),
            "full_recall": self.full_recall,
            "cost_to_full_recall": self.cost_to_full_recall,
        }


def _config_for(case: BenchmarkCase, planner: str) -> ScanConfig:
    planner_config = PlannerConfig(
        kind=planner,
        seed=case.seed,
        cost_budget=case.budget,
        prefix_len=case.prefix_len,
        confirm_min_attempts=case.confirm_min_attempts,
        confidence_threshold=case.confidence_threshold,
        reserved_ratio=0.15,
        prune_mode=case.prune_mode,
    )
    network_config = NetworkConfig(
        concurrency=128,
        base_timeout_s=case.base_timeout_s,
        min_timeout_s=min(0.15, case.base_timeout_s),
        max_timeout_s=case.max_timeout_s,
        max_attempts=3,
        max_hosts=max(64, len(case.hosts)),
        max_ports=max(1024, len(case.ports)),
    )
    return ScanConfig(
        targets=case.hosts,
        ports=case.ports,
        backend="fake",
        run_label=f"bench:{planner}:{case.scenario}:b{case.budget}",
        planner=planner_config,
        network=network_config,
    ).validate()


async def run_benchmark(case: BenchmarkCase, out_dir: str | Path) -> list[BenchmarkResult]:
    """Run every planner in ``case`` against the same scenario and collect metrics."""
    case.validate()
    catalog: dict[str, NetworkScenario] = builtin_scenarios()
    if case.scenario not in catalog:
        raise ConfigError("unknown benchmark scenario", scenario=case.scenario, known=sorted(catalog))
    scenario = catalog[case.scenario]
    truth = scenario.ground_truth(case.hosts, case.ports)
    totals = {
        "open": sum(1 for state in truth.values() if state is PortState.OPEN),
        "closed": sum(1 for state in truth.values() if state is PortState.CLOSED),
        "filtered": sum(1 for state in truth.values() if state is PortState.FILTERED),
    }

    results: list[BenchmarkResult] = []
    base = Path(out_dir)
    for planner in case.planners:
        config = _config_for(case, planner)
        engine = ScanEngine(
            config,
            backend=FakeBackend(scenario=scenario, allow=list(case.hosts), config=config),
            out_dir=base,
            run_id=f"{case.scenario}-b{case.budget}-{planner}-seed{case.seed}",
        )
        run = await engine.run()
        summary = run.summary
        false_open = 0
        open_found = 0
        closed_found = 0
        filtered_found = 0
        for pair, result in run.results.items():
            expected = truth.get(pair, PortState.UNDETERMINED)
            if result.state is PortState.OPEN:
                if expected is PortState.OPEN:
                    open_found += 1
                else:
                    false_open += 1
            elif result.state is PortState.CLOSED and expected is PortState.CLOSED:
                closed_found += 1
            elif result.state is PortState.FILTERED and expected is PortState.FILTERED:
                filtered_found += 1

        first_open_cost = _nth_open_cost(run.evidence_path, 1)
        full_recall_cost = _nth_open_cost(run.evidence_path, totals["open"]) if totals["open"] else 0
        results.append(
            BenchmarkResult(
                planner=planner,
                scenario=case.scenario,
                seed=case.seed,
                budget=case.budget,
                dispatched=summary.dispatched,
                cost_spent=summary.cost_spent,
                open_found=open_found,
                open_total=totals["open"],
                closed_found=closed_found,
                closed_total=totals["closed"],
                filtered_found=filtered_found,
                filtered_total=totals["filtered"],
                undetermined=summary.undetermined_ports,
                cost_of_filtered=summary.cost_of_filtered,
                time_to_first_open_cost=first_open_cost,
                cost_to_full_recall=full_recall_cost if open_found == totals["open"] else None,
                confirms=summary.confirms,
                pruned_segments=summary.pruned_segments,
                elapsed_s=summary.elapsed_s,
                run_id=run.run_id,
                evidence=str(run.evidence_path),
                false_open=false_open,
            )
        )
    return results


def _nth_open_cost(evidence_path: str | Path, n: int) -> int | None:
    """Cost at the moment the n-th open port was observed.

    This is the scheduler's own answer to 'how long until I had the answer?', and it
    is readable straight out of the evidence log, so anyone can re-derive it.
    """
    seen = 0
    for record in read_records(evidence_path):
        if record.kind != "probe":
            continue
        if record.data.get("observation", {}).get("state") == PortState.OPEN.value:
            seen += 1
            if seen >= n:
                return int(record.data.get("cost_spent", 0))
    return None


def compare(results: Sequence[BenchmarkResult], baseline: str = "fixed") -> dict[str, Any]:
    """Summarise the difference between each planner and ``baseline``.

    Deltas are percentages of the baseline so a reader can see '16% less wasted
    budget' rather than a bare integer. When the baseline value is zero the delta is
    reported as ``None`` rather than as a fake 100%.
    """
    by_name = {item.planner: item for item in results}
    base = by_name.get(baseline)
    if base is None:
        return {"baseline_missing": baseline}
    out: dict[str, Any] = {}
    for item in results:
        if item.planner == baseline:
            continue
        entry: dict[str, Any] = {
            "recall_delta_pp": round((item.recall - base.recall) * 100, 2),
            "waste_ratio_delta_pp": round((item.waste_ratio - base.waste_ratio) * 100, 2),
            "cost_delta_pct": _pct(item.cost_spent, base.cost_spent),
            "open_found_delta": item.open_found - base.open_found,
            "pruned_segments": item.pruned_segments,
            "confirms": item.confirms,
        }
        if base.time_to_first_open_cost and item.time_to_first_open_cost:
            entry["ttfo_cost_delta_pct"] = _pct(item.time_to_first_open_cost, base.time_to_first_open_cost)
        if base.cost_to_full_recall and item.cost_to_full_recall:
            entry["cost_to_full_recall_delta_pct"] = _pct(
                item.cost_to_full_recall, base.cost_to_full_recall
            )
        out[item.planner] = entry
    return out


def _pct(value: float, baseline: float) -> float | None:
    if baseline == 0:
        return None
    return round((value - baseline) / baseline * 100, 2)


async def budget_sweep(  # noqa: PLR0913 - a sweep is defined by these six knobs
    scenario: str,
    budgets: Sequence[int],
    out_dir: str | Path,
    *,
    seed: int = 1337,
    planners: Sequence[str] = DEFAULT_PLANNERS,
    prune_mode: str = "defer",
) -> list[BudgetSweepRow]:
    """Run the same scenario at several budgets and flatten the results into rows.

    The point is to locate the budget at which each policy first reaches full recall
    without exceeding it - the honest way to compare policies that trade cost against
    completeness.
    """
    rows: list[BudgetSweepRow] = []
    for budget in budgets:
        case = default_case(scenario, budget, seed)
        case.planners = tuple(planners)
        case.prune_mode = prune_mode
        for result in await run_benchmark(case, out_dir):
            rows.append(
                BudgetSweepRow(
                    scenario=scenario,
                    budget=budget,
                    planner=result.planner,
                    recall=result.recall,
                    cost_spent=result.cost_spent,
                    waste_ratio=result.waste_ratio,
                    full_recall=result.open_found == result.open_total,
                    cost_to_full_recall=result.cost_to_full_recall,
                )
            )
    return rows


def write_results(path: str | Path, payload: Mapping[str, Any]) -> Path:
    """Write the benchmark payload.

    ``path`` may be a directory (``benchmark.json`` is created inside it, the default
    layout produced by the harness) or a full file name, which is what ``--save``
    means. Earlier versions always appended ``benchmark.json`` and silently ignored a
    requested file name.
    """
    target = Path(path)
    if target.suffix.lower() != ".json":
        target = target / "benchmark.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def environment() -> dict[str, Any]:
    """Record the environment so a result can be attributed to a machine + version."""
    return {
        "schedprobe": __version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
    }


def default_case(scenario: str, budget: int, seed: int = 1337) -> BenchmarkCase:
    """Build the standard case used in the published results."""
    scenarios = builtin_scenarios()
    if scenario not in scenarios:
        raise ConfigError("unknown scenario", scenario=scenario, known=sorted(scenarios))
    spec = scenarios[scenario]
    hosts = tuple(spec.hosts)
    if scenario == "wide-sweep":
        ports = tuple(range(1, 1025))
    elif scenario == "segmented-sweep":
        ports = tuple(range(1, 65))
    elif scenario == "mixed-lossy":
        ports = (22, 80, 443, 3306, 6379, 8080)
    else:
        ports = (22, 80, 443, 3306, 6379, 8080, 8443)
    return BenchmarkCase(scenario=scenario, hosts=hosts, ports=ports, budget=budget, seed=seed)


def all_cases(budget: int, seed: int = 1337) -> list[BenchmarkCase]:
    """Every scenario, for the full published run."""
    return [default_case(name, budget, seed) for name in sorted(builtin_scenarios())]
