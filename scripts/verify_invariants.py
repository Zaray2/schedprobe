"""Invariant matrix: run every scenario/planner/budget combination and assert four things.

This is the project's acceptance test at the systems level. Each of the 72 runs must satisfy:

1. **Budget hard cap** - on every record in the evidence log,
   ``cost_spent + reserved_units <= budget``. Read from the artifact, not from an
   internal counter, so the check is the same one a third party would perform.
2. **Concurrency cap** - the in-flight set never exceeds ``network.concurrency``.
3. **Chain integrity** - the hash chain verifies.
4. **Replay determinism** - re-deriving the schedule offline reproduces every decision.

Runs go to a temporary directory that is removed afterwards, so the repository is never
littered. Exit code is 0 only when every run is clean; otherwise the offending
combinations are printed.

    python scripts/verify_invariants.py
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schedprobe.backends.fake import FakeBackend, builtin_scenarios  # noqa: E402
from schedprobe.config import NetworkConfig, PlannerConfig, ScanConfig  # noqa: E402
from schedprobe.engine import ScanEngine  # noqa: E402
from schedprobe.evidence import read_records, verify_chain  # noqa: E402
from schedprobe.replay import replay_chain  # noqa: E402

MODES = ("defer", "drop")
BUDGETS = (15000, 150000)
PLANNERS = ("adaptive", "fixed", "random")
WIDE_PORTS = tuple(range(1, 65))
NARROW_PORTS = (22, 80, 443, 3306, 6379, 8080, 8443)


def ports_for(scenario: str) -> tuple[int, ...]:
    return WIDE_PORTS if scenario == "segmented-sweep" else NARROW_PORTS


def check_one(scenario_name: str, mode: str, budget: int, kind: str, out_dir: str) -> list[str]:
    """Run one configuration and return the list of invariant violations it produced."""
    scenario = builtin_scenarios()[scenario_name]
    hosts = tuple(sorted(scenario.hosts))
    planner_config = PlannerConfig(
        kind=kind, seed=1337, cost_budget=budget, prune_mode=mode, verify_heap=True
    )
    config = ScanConfig(
        targets=hosts,
        ports=ports_for(scenario_name),
        backend="fake",
        planner=planner_config,
        network=NetworkConfig(concurrency=64, max_hosts=128, max_ports=1024),
    ).validate()
    engine = ScanEngine(
        config,
        backend=FakeBackend(scenario=scenario, allow=list(hosts), config=config),
        out_dir=out_dir,
        run_id=f"{scenario_name}-{mode}-{budget}-{kind}",
    )
    run = asyncio.run(engine.run())

    probes = [record for record in read_records(run.evidence_path) if record.kind == "probe"]
    problems: list[str] = []
    if any(
        record.data["cost_spent"] + record.data["reserved_units"] > record.data["budget"]
        for record in probes
    ):
        problems.append("BUDGET")
    if any(len(record.data["inflight_pairs"]) > config.network.concurrency for record in probes):
        problems.append("INFLIGHT")
    if not verify_chain(run.evidence_path).ok:
        problems.append("CHAIN")
    report = replay_chain(run.evidence_path)
    if not report.ok:
        problems.append(f"REPLAY({len(report.divergences)})")
    if run.manifest["probe_errors"]:
        problems.append("PROBE_ERRORS")
    return problems


def main() -> int:
    logging.basicConfig(level=logging.ERROR, format="%(message)s")
    out_dir = tempfile.mkdtemp(prefix="schedprobe-invariants-")
    violations: list[tuple[str, str, int, str, list[str]]] = []
    runs = 0
    try:
        for scenario_name in sorted(builtin_scenarios()):
            for mode in MODES:
                for budget in BUDGETS:
                    for kind in PLANNERS:
                        runs += 1
                        problems = check_one(scenario_name, mode, budget, kind, out_dir)
                        if problems:
                            violations.append((scenario_name, mode, budget, kind, problems))
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)

    print(f"checked {runs} runs across {len(builtin_scenarios())} scenarios")
    if violations:
        for row in violations:
            print(f"  VIOLATION {row[0]} mode={row[1]} budget={row[2]} planner={row[3]}: {row[4]}")
        return 1
    print("violations: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
