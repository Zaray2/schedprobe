"""Is the adaptive policy actually worse on a wide sweep? A controlled experiment.

The published results record that ``adaptive`` reaches 33% recall on ``wide-sweep`` where
``fixed`` reaches 67%, and that number has been reported as a policy regression. This
script tests that reading rather than repeating it, and it does not come out the way the
raw numbers suggest.

**Part A - how much signal is in that number?** ``wide-sweep`` contains *three* open
ports in 3072 pairs, all three on the same host at the lowest port numbers. Comparing
33% with 67% therefore compares finding one port against finding two. To find out whether
anything mechanistic sits underneath, part A varies exactly one policy knob at a time and
also reports the coverage gap (planned pairs never probed), which is the quantity that
should move if pruning were the cause.

**Part B - a comparison with resolution.** ``bench.dense_sweep_scenario`` generates a
sweep whose number of open ports and number of responsive hosts are parameters, so recall
is measured with more than three samples. Each configuration is then repeated over several
seeds and reported as mean / min / max / spread, because a budget-starved sweep has large
per-run variance and a single seed cannot separate a policy difference from luck.

Run both:

    python scripts/experiment_adaptive_regression.py --full --save docs/research/adaptive-experiment.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schedprobe.backends.fake import FakeBackend, NetworkScenario, builtin_scenarios  # noqa: E402
from schedprobe.bench import (  # noqa: E402
    dense_sweep_scenario,
    repeat_case,
    synthetic_case,
)
from schedprobe.config import NetworkConfig, PlannerConfig, ScanConfig  # noqa: E402
from schedprobe.engine import ScanEngine  # noqa: E402
from schedprobe.evidence import read_records  # noqa: E402
from schedprobe.models import PortState  # noqa: E402


@dataclass(frozen=True)
class Arm:
    """One experimental condition: the shipped planner plus one deliberate change."""

    name: str
    planner: str
    change: str
    prune_after: int = 3
    prune_min_planned: int = 3
    prune_mode: str = "defer"
    confirm_max_drop_ratio: float = 0.5

    def planner_config(self, budget: int, seed: int) -> PlannerConfig:
        return PlannerConfig(
            kind=self.planner,
            seed=seed,
            cost_budget=budget,
            prune_mode=self.prune_mode,
            prune_after_consecutive_timeouts=self.prune_after,
            prune_min_planned=self.prune_min_planned,
            confirm_min_attempts=1,
            confirm_max_drop_ratio=self.confirm_max_drop_ratio,
            verify_heap=True,
        )


ARMS: tuple[Arm, ...] = (
    Arm("adaptive (shipped)", "adaptive", "-"),
    Arm(
        "adaptive, no prune",
        "adaptive",
        "prune thresholds raised out of reach",
        prune_after=10**9,
        prune_min_planned=10**9,
    ),
    Arm("adaptive, late prune", "adaptive", "12 consecutive stalls instead of 3", prune_after=12),
    Arm(
        "adaptive, min sample 64",
        "adaptive",
        "64 planned pairs before a segment may go",
        prune_min_planned=64,
    ),
    Arm("adaptive, no confirm", "adaptive", "confirmation gate closed", confirm_max_drop_ratio=0.0),
    Arm("adaptive, always confirm", "adaptive", "confirmation gate wide open", confirm_max_drop_ratio=1.0),
    Arm("adaptive, drop mode", "adaptive", "abandoned pairs removed", prune_mode="drop"),
    Arm("fixed (baseline)", "fixed", "input order"),
    Arm("random (baseline)", "random", "shuffled order"),
    Arm("fixed-longtimeout (baseline)", "fixed-longtimeout", "input order, long timeouts"),
)


@dataclass
class Observation:
    arm: str
    budget: int
    seed: int
    recall: float
    precision: float
    open_found: int
    open_total: int
    cost_spent: int
    coverage_gap: int
    pairs_planned: int
    pruned_segments: int
    confirms: int
    cost_to_full_recall: int | None


def _nth_open_cost(evidence_path: Path, n: int) -> int | None:
    """Cost at which the n-th open port was confirmed, read back from the evidence log."""
    if n < 1:
        return None
    seen = 0
    for record in read_records(evidence_path):
        if record.kind != "probe":
            continue
        observation = record.data.get("observation") or {}
        if observation.get("state") == "open":
            seen += 1
            if seen == n:
                return int(record.data.get("cost_spent", 0))
    return None


async def run_arm(  # noqa: PLR0913, PLR0917 - an experimental condition, listed once
    arm: Arm,
    scenario: NetworkScenario,
    hosts: tuple[str, ...],
    ports: tuple[int, ...],
    budget: int,
    seed: int,
    out_dir: Path,
) -> Observation:
    truth = scenario.ground_truth(hosts, ports)
    open_total = sum(1 for state in truth.values() if state is PortState.OPEN)

    config = ScanConfig(
        targets=hosts,
        ports=ports,
        backend="fake",
        planner=arm.planner_config(budget, seed),
        network=NetworkConfig(concurrency=128, max_hosts=4096, max_ports=4096, rate_limit_pps=0.0),
    ).validate()
    run_id = f"{scenario.name}-b{budget}-s{seed}-{arm.name.replace(' ', '_').replace(',', '')}"
    engine = ScanEngine(
        config,
        backend=FakeBackend(scenario=scenario, allow=list(hosts), config=config),
        out_dir=out_dir,
        run_id=run_id[:110],
    )
    run = await engine.run()

    open_found = 0
    false_open = 0
    for pair, result in run.results.items():
        if result.state is PortState.OPEN:
            if truth.get(pair) is PortState.OPEN:
                open_found += 1
            else:
                false_open += 1

    summary = run.summary
    planned = int(summary.pairs_total)
    touched = int(summary.pairs_touched)
    return Observation(
        arm=arm.name,
        budget=budget,
        seed=seed,
        recall=open_found / open_total if open_total else 1.0,
        precision=open_found / (open_found + false_open) if (open_found + false_open) else 1.0,
        open_found=open_found,
        open_total=open_total,
        cost_spent=int(summary.cost_spent),
        coverage_gap=max(0, planned - touched),
        pairs_planned=planned,
        pruned_segments=int(summary.pruned_segments),
        confirms=int(summary.confirms),
        cost_to_full_recall=_nth_open_cost(run.evidence_path, open_total) if open_total else None,
    )


def render_part_a(observations: list[Observation], budgets: list[int]) -> str:
    lines: list[str] = []
    for budget in budgets:
        rows = [o for o in observations if o.budget == budget]
        if not rows:
            continue
        lines.append(f"### wide-sweep, budget = {budget}")
        lines.append(
            f"{'arm':<30} {'recall':>7} {'opens':>7} {'cost':>8} {'gap':>7} "
            f"{'planned':>8} {'pruned':>7} {'confirms':>9} {'full-recall':>12}"
        )
        lines.append("-" * 106)
        for row in sorted(rows, key=lambda r: -r.recall):
            cost = str(row.cost_to_full_recall) if row.cost_to_full_recall is not None else "never"
            lines.append(
                f"{row.arm:<30} {row.recall:>6.1%} "
                f"{row.open_found:>3}/{row.open_total:<3} {row.cost_spent:>8} "
                f"{row.coverage_gap:>7} {row.pairs_planned:>8} {row.pruned_segments:>7} "
                f"{row.confirms:>9} {cost:>12}"
            )
        lines.append("")
    return "\n".join(lines)


def render_part_b(rows: list) -> str:
    lines = [
        f"{'scenario':<26} {'planner':<20} {'mean':>7} {'min':>7} {'max':>7} {'spread':>7} {'seeds':>6}"
    ]
    lines.append("-" * 84)
    for row in sorted(rows, key=lambda r: (r["scenario"], -r["mean_recall"])):
        lines.append(
            f"{row['scenario']:<26} {row['planner']:<20} {row['mean_recall']:>6.1%} "
            f"{row['min_recall']:>6.1%} {row['max_recall']:>6.1%} "
            f"{row['spread']:>6.1%} {len(row['seeds']):>6}"
        )
    return "\n".join(lines)


async def part_a(args: argparse.Namespace, out_dir: Path) -> tuple[list[Observation], list[int]]:
    scenario = builtin_scenarios()["wide-sweep"]
    hosts = tuple(scenario.hosts)
    ports = tuple(range(1, args.ports + 1))
    budgets = [60000, 120000, 250000] if args.full else [120000]
    observations: list[Observation] = []
    for budget in budgets:
        print(f"  part A: {len(ARMS)} arms at budget={budget}", file=sys.stderr)
        for arm in ARMS:
            observations.append(await run_arm(arm, scenario, hosts, ports, budget, args.seed, out_dir))
    return observations, budgets


async def part_b(args: argparse.Namespace, out_dir: Path) -> list[dict]:
    """A comparison with enough open ports and enough seeds to mean something."""
    outputs: list[dict] = []
    grid = [
        # (hosts, ports, opens_per_host, dead_fraction, budget)
        (8, 1024, 3, 0.0, 120000),
        (8, 1024, 3, 0.0, 300000),
        (8, 1024, 3, 0.75, 300000),
        (16, 512, 2, 0.5, 300000),
    ]
    seeds = tuple(range(1337, 1337 + args.seeds))
    for hosts, ports, per_host, dead, budget in grid:
        scenario = dense_sweep_scenario(
            hosts=hosts, ports=ports, opens_per_host=per_host, dead_fraction=dead
        )
        port_list = tuple(range(1, ports + 1))
        case = synthetic_case(scenario, port_list, budget, seed=seeds[0])
        label = f"{hosts}h x {ports}p dead={dead:.0%} b{budget}"
        print(f"  part B: {label} over {len(seeds)} seeds", file=sys.stderr)
        for result in await repeat_case(scenario, case, seeds, out_dir):
            payload = result.to_dict()
            payload["scenario"] = label
            payload["budget"] = budget
            outputs.append(payload)
    return outputs


async def main_async(args: argparse.Namespace) -> int:
    out_dir = Path(tempfile.mkdtemp(prefix="schedprobe-exp-"))
    payload: dict = {"seed": args.seed, "seeds_in_part_b": args.seeds}
    try:
        observations, budgets = await part_a(args, out_dir)
        print("=" * 106)
        print("PART A - the published claim's resolution (wide-sweep: 3 open ports / 3072 pairs)")
        print("'gap' = planned pairs never probed; if pruning were the cause, it would move.")
        print("=" * 106)
        print()
        print(render_part_a(observations, budgets))
        payload["part_a"] = {
            "arms": [a.__dict__ for a in ARMS],
            "observations": [o.__dict__ for o in observations],
        }

        part_b_rows = await part_b(args, out_dir)
        print("=" * 84)
        print("PART B - a comparison with resolution (generated sweeps, repeated over seeds)")
        print("=" * 84)
        print()
        print(render_part_b(part_b_rows))
        payload["part_b"] = part_b_rows
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)

    if args.save:
        target = Path(args.save)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"saved: {target}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--full", action="store_true", help="run every budget level in part A")
    parser.add_argument("--ports", type=int, default=1024, help="ports per host in part A")
    parser.add_argument("--seed", type=int, default=1337, help="seed for part A")
    parser.add_argument("--seeds", type=int, default=8, help="how many seeds in part B")
    parser.add_argument("--save", default="", help="write observations as JSON")
    ns = parser.parse_args()
    logging.basicConfig(level=logging.ERROR, format="%(message)s")
    return asyncio.run(main_async(ns))


if __name__ == "__main__":
    raise SystemExit(main())
