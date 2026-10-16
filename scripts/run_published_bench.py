"""Run the published benchmark suite and write docs/research/benchmark-raw.json.

Reproducible by anyone with the repository::

    python scripts/run_published_bench.py

Uses only the deterministic simulator backend, so it needs no network access and
produces byte-identical numbers on any machine that runs the same version.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schedprobe.bench import (  # noqa: E402
    budget_sweep,
    compare,
    default_case,
    environment,
    run_benchmark,
)

OUT_DIR = ROOT / "bench" / "runs"
RAW_PATH = ROOT / "docs" / "research" / "benchmark-raw.json"

SWEEPS: dict[str, tuple[int, ...]] = {
    "segmented-sweep": (5000, 15000, 30000, 60000, 120000, 200000),
    "blackhole-segment": (15000, 40000, 80000, 150000, 300000),
    "segmented-filtered": (15000, 40000, 80000, 150000, 300000),
    "wide-sweep": (20000, 60000, 120000, 250000),
    "mixed-lossy": (5000, 15000, 40000),
    "healthy": (5000, 20000),
}

HEADLINE: tuple[tuple[str, int], ...] = (
    ("segmented-sweep", 150000),
    ("segmented-sweep", 30000),
    ("segmented-sweep", 5000),
    ("blackhole-segment", 80000),
    ("segmented-filtered", 40000),
    ("wide-sweep", 60000),
    ("mixed-lossy", 15000),
    ("healthy", 5000),
)


def main() -> int:
    logging.basicConfig(level=logging.ERROR, format="%(message)s")
    payload: dict[str, object] = {"environment": environment(), "headline": {}, "sweeps": {}}

    print("== cost to full recall (prune_mode=defer, seed=1337) ==")
    for scenario, budgets in SWEEPS.items():
        rows = asyncio.run(budget_sweep(scenario, list(budgets), OUT_DIR))
        payload["sweeps"][scenario] = [row.to_dict() for row in rows]
        print(f"\n### {scenario}")
        by_planner: dict[str, list[str]] = {}
        for row in rows:
            verdict = f"{row.cost_to_full_recall}" if row.full_recall else f"no ({row.recall:.0%})"
            by_planner.setdefault(row.planner, []).append(f"b{row.budget}={verdict}")
        for planner, cells in sorted(by_planner.items()):
            print(f"  {planner:<18} " + "  ".join(cells))

    print("\n== headline cases ==")
    for scenario, budget in HEADLINE:
        case = default_case(scenario, budget)
        results = asyncio.run(run_benchmark(case, OUT_DIR))
        key = f"{scenario}@{budget}"
        payload["headline"][key] = {
            "runs": [item.to_dict() for item in results],
            "delta_vs_fixed": compare(results, "fixed"),
        }
        print(f"\n### {scenario} budget={budget} ({len(case.hosts)} hosts x {len(case.ports)} ports)")
        for item in results:
            print(
                f"  {item.planner:<18} recall={item.recall:6.1%} cost={item.cost_spent:>8} "
                f"waste={item.waste_ratio:6.1%} opens={item.open_found}/{item.open_total} "
                f"full_recall_cost={item.cost_to_full_recall}"
            )

    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    RAW_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {RAW_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
