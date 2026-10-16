"""Before/after measurement for the segment-score band fix.

The reviewer's scenario, built literally: one /24 that mixes a host with many open ports
with hosts that are entirely filtered. That is the shape a real engagement usually has -
one interesting machine on a subnet full of quiet ones - and it is the shape the old
scoring model mishandled, because a segment holding a single open port among many timeouts
scored *worse* than a segment that had answered nothing at all.

This script measures the consequence rather than the score: how many of the open ports
does the adaptive planner actually find, with the old formula and with the new one, under
the same seed and budget.

**Measured result: recall is identical, and that is reported rather than buried.** On every
configuration tried - one rich host in one /24 against one dead /24, and against seven dead
/24s, at budgets 20k/60k/150k, three seeds each - both formulas reach 100% recall. The
probe counts differ (73 vs 79 touched pairs at budget 60k with seven dead segments) but not
in a consistent direction, and the cost difference runs the other way.

The reason is that pruning and the deferral penalty already bound the damage: a dead segment
is abandoned after three consecutive timeouts (``prune_after_consecutive_timeouts``), and a
deferred segment carries ``deferred_penalty`` on top of its score. So a wrong segment
ordering costs a few probes per dead segment rather than the final answer.

The fix is kept anyway, for a narrower reason: the old formula contradicted its own stated
contract. ``health_score``'s docstring says a segment that has only ever timed out is "the
worst possible place to spend budget", yet a segment that had answered once and then timed
out scored 1.499 against the dead segment's 1.000 - worse than the worst possible place.
The bands are now disjoint, which is what ``tests/test_segment_policy.py`` pins.

Anyone reading this later: do not cite this change as a performance improvement. It is a
correctness fix with a small, mixed effect on waste, and it was found by a reviewer rather
than by the benchmark - which is itself worth remembering.

    python scripts/measure_segment_fix.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schedprobe.backends.fake import FakeBackend, NetworkScenario  # noqa: E402
from schedprobe.config import NetworkConfig, PlannerConfig, ScanConfig  # noqa: E402
from schedprobe.engine import ScanEngine  # noqa: E402
from schedprobe.models import PortState  # noqa: E402

PORTS = tuple(range(1, 257))


def mixed_liveness_scenario(
    *, rich_hosts: int = 1, quiet_hosts: int = 7, opens_on_rich: int = 40, prefix: str = "10.90"
) -> NetworkScenario:
    """A rich host in its own /24, and a *different* /24 that is entirely dead.

    The two segments have to be separate, and that is not a detail: with everything in one
    /24 there is a single segment, so segment-level ordering has nothing to order and the
    scoring bug cannot express itself. The first version of this script made exactly that
    mistake and measured identical before/after numbers, which is a result about the
    scenario rather than about the fix.
    """
    rules: dict[str, dict] = {}
    for index in range(1, rich_hosts + 1):
        rules[f"{prefix}.0.{index}"] = {
            "ports": {str(port): "open" for port in PORTS[:opens_on_rich]},
            "default": "filtered",
        }
    # One dead host per /24, so there are `quiet_hosts` dead *segments* rather than one.
    # With a single dead segment the planner wastes at most a few probes there before
    # pruning it; spreading them out multiplies that waste, which is the case where a
    # wrong segment ordering can actually be observed.
    for index in range(1, quiet_hosts + 1):
        rules[f"{prefix}.{index}.1"] = {"unreachable": True}
    return NetworkScenario(
        name=f"mixed-liveness-{rich_hosts}rich-{quiet_hosts}quiet",
        hosts=rules,
        loss_rate=0.0,
        latency_ms=(1, 3),
        description=(
            f"{rich_hosts} host(s) with {opens_on_rich} open ports mixed into a /24 with "
            f"{quiet_hosts} entirely filtered hosts"
        ),
    )


async def run(scenario: NetworkScenario, budget: int, seed: int, out_dir: Path) -> dict:
    hosts = tuple(sorted(scenario.hosts))
    truth = scenario.ground_truth(hosts, PORTS)
    total_open = sum(1 for state in truth.values() if state is PortState.OPEN)

    planner_config = PlannerConfig(
        kind="adaptive", seed=seed, cost_budget=budget, prune_mode="defer", verify_heap=True
    )
    config = ScanConfig(
        targets=hosts,
        ports=PORTS,
        backend="fake",
        planner=planner_config,
        network=NetworkConfig(concurrency=128, max_hosts=4096, max_ports=4096, rate_limit_pps=0.0),
    ).validate()
    engine = ScanEngine(
        config,
        backend=FakeBackend(scenario=scenario, allow=list(hosts), config=config),
        out_dir=out_dir,
        run_id=f"{scenario.name}-b{budget}-s{seed}",
    )
    result = await engine.run()
    found = sum(
        1
        for pair, probe in result.results.items()
        if probe.state is PortState.OPEN and truth.get(pair) is PortState.OPEN
    )
    return {
        "open_total": total_open,
        "open_found": found,
        "recall": found / total_open if total_open else 1.0,
        "cost_spent": int(result.summary.cost_spent),
        "pairs_touched": int(result.summary.pairs_touched),
        "pairs_total": int(result.summary.pairs_total),
        "pruned_segments": int(result.summary.pruned_segments),
    }


async def main() -> int:
    scenario = mixed_liveness_scenario()
    truth = scenario.ground_truth(tuple(sorted(scenario.hosts)), PORTS)
    total_open = sum(1 for state in truth.values() if state is PortState.OPEN)

    print("=" * 76)
    print("scenario:", scenario.name)
    print(" ", scenario.description)
    print(f"  pairs={len(scenario.hosts) * len(PORTS)}  open_ports={total_open}")
    print("=" * 76)
    print()

    out_dir = Path(tempfile.mkdtemp(prefix="schedprobe-segfix-"))
    rows = []
    try:
        for budget in (20000, 60000, 150000):
            for seed in (1337, 4242, 9001):
                rows.append(
                    {"budget": budget, "seed": seed, **(await run(scenario, budget, seed, out_dir))}
                )
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)

    print(f"{'budget':>8} {'seed':>6} {'recall':>8} {'found':>9} {'cost':>8} {'touched':>9} {'pruned':>7}")
    print("-" * 60)
    for row in rows:
        print(
            f"{row['budget']:>8} {row['seed']:>6} {row['recall']:>7.1%} "
            f"{row['open_found']:>4}/{row['open_total']:<4} {row['cost_spent']:>8} "
            f"{row['pairs_touched']:>9} {row['pruned_segments']:>7}"
        )
    mean = sum(row["recall"] for row in rows) / len(rows)
    print(f"\nmean recall: {mean:.1%}   (simulator, deterministic per seed)")

    target = ROOT / "docs" / "research" / "segment-fix-measurement.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "scenario": scenario.name,
                "description": scenario.description,
                "open_ports": total_open,
                "ports": len(PORTS),
                "hosts": len(scenario.hosts),
                "rows": rows,
                "mean_recall": round(mean, 4),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"saved: {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR, format="%(message)s")
    raise SystemExit(asyncio.run(main()))
