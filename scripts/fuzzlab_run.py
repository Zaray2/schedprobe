"""Run the FuzzLab scheduling experiment.

    python scripts/fuzzlab_run.py build
    python scripts/fuzzlab_run.py pilot          # one seed, short budget: does it work at all
    python scripts/fuzzlab_run.py run --budget 120 --seeds 5

Every campaign is recorded into a hash-chained evidence log before its numbers are used, so
the report can point at the run that produced each figure. That is the part of SchedProbe
being reused: the same append-only, tamper-evident record that makes a probe schedule
auditable also makes a fuzzing result traceable.
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schedprobe.evidence import EvidenceLog  # noqa: E402
from schedprobe.fuzzlab import ARMS, Experiment, arm_by_name, report, runner  # noqa: E402  # noqa: E402
from schedprobe.fuzzlab.model import CampaignResult  # noqa: E402

DATA_DIR = ROOT / "docs" / "research" / "fuzzlab-data"


def _environment() -> dict[str, object]:
    """What a reader needs to judge whether the numbers are reproducible on their machine."""
    probe = runner.wsl(["clang --version | head -1; afl-fuzz -h 2>&1 | head -1; uname -m"], timeout=90)
    return {
        "host_os": platform.system(),
        "host_python": platform.version(),
        "fuzzing_os": "Alpine Linux (WSL2)",
        "toolchain": probe.stdout.strip().splitlines(),
        "corpus_digest": runner.corpus_fingerprint(),
        "power_schedule": "AFL++ default (-p explore)",
        "sanitizer": "ASAN (-fsanitize=address via AFL_USE_ASAN=1)",
    }


def cmd_build(_args: argparse.Namespace) -> int:
    if not runner.have_wsl():
        print("FAIL: WSL distribution 'jump1' is not reachable", file=sys.stderr)
        return 1
    paths = runner.build(ROOT)
    print("build ok:")
    for name, path in paths.items():
        print(f"  {name}: {path}")
    print(f"  corpus digest: {runner.corpus_fingerprint()}")
    return 0


def cmd_pilot(args: argparse.Namespace) -> int:
    """One seed, two arms, short budget: proves the harness before any claim is made."""
    runner.build(ROOT)
    experiment = Experiment(
        name="fuzzlab-pilot",
        target="cjson-1.7.19",
        budget_kind="seconds",
        budget_limit=args.budget,
        seeds=(args.seed,),
    )
    experiment.environment = _environment()
    log_path = DATA_DIR / "pilot.evidence.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists():
        log_path.unlink()

    with EvidenceLog(log_path, "fuzzlab-pilot") as log:
        log.append("experiment", {"name": experiment.name, "environment": experiment.environment})
        for name in ("stock", "all", "full"):
            arm = arm_by_name(name)
            started = time.time()
            stats, crashes, mechanism = runner.run_campaign(
                arm, args.seed, budget_seconds=args.budget, repo_root=ROOT
            )
            elapsed = round(time.time() - started, 1)
            experiment.add(
                CampaignResult(
                    arm=arm.name,
                    seed=args.seed,
                    stats=stats,
                    crashes=crashes,
                    mechanism=mechanism,
                )
            )
            log.append(
                "campaign",
                {
                    "arm": arm.name,
                    "seed": args.seed,
                    "execs": stats.execs_done,
                    "edges": stats.edges_found,
                    "crashes": len(crashes),
                    "distinct": len({c.signature for c in crashes}),
                    "wall_s": elapsed,
                },
            )
            print(
                f"  {arm.name:<10} execs={stats.execs_done:<7} edges={stats.edges_found:<5} "
                f"crashes={len(crashes)} distinct={len({c.signature for c in crashes})} "
                f"({elapsed}s)"
            )

    summaries = experiment.summaries(ARMS)
    print()
    print(report.render_arm_table(summaries))
    print()
    print(f"evidence: {log_path}")
    json_path, md_path = report.write_results(
        experiment,
        summaries,
        [],
        out_dir=DATA_DIR,
        baseline="stock",
        extra_notes=["pilot run: one seed only, not a comparison"],
    )
    print(f"json: {json_path}")
    print(f"md:   {md_path}")
    _cleanup_if_ok(args)
    return 0


def _cleanup_if_ok(args: argparse.Namespace) -> None:
    """Remove the WSL work tree only when the run succeeded.

    An earlier version cleaned unconditionally, which meant a failed campaign destroyed the
    logs that explained the failure. Keeping the work tree on error is the difference between
    a debuggable experiment and an anecdote.
    """
    if getattr(args, "keep", False):
        print(f"work tree kept: {runner.WSL_ROOT}")
        return
    runner.clean()


def cmd_run(args: argparse.Namespace) -> int:
    arms = [arm_by_name(name) for name in args.arms.split(",")] if args.arms else list(ARMS)
    seeds = tuple(args.seed_base + index for index in range(args.seeds))
    runner.build(ROOT)
    experiment = Experiment(
        name=args.name,
        target="cjson-1.7.19",
        budget_kind="seconds",
        budget_limit=args.budget,
        seeds=seeds,
    )
    experiment.environment = _environment()
    log_path = DATA_DIR / f"{args.name}.evidence.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists():
        log_path.unlink()

    mechanisms: list[dict[str, object]] = []
    with EvidenceLog(log_path, args.name) as log:
        log.append(
            "experiment",
            {
                "name": args.name,
                "budget_seconds": args.budget,
                "seeds": list(seeds),
                "arms": [arm.name for arm in arms],
                "environment": experiment.environment,
            },
        )
        for arm in arms:
            for seed in seeds:
                started = time.time()
                stats, crashes, mechanism = runner.run_campaign(
                    arm, seed, budget_seconds=args.budget, repo_root=ROOT
                )
                elapsed = round(time.time() - started, 1)
                experiment.add(
                    CampaignResult(
                        arm=arm.name,
                        seed=seed,
                        stats=stats,
                        crashes=crashes,
                        mechanism=mechanism,
                    )
                )
                decisions = runner.decision_summary(arm, seed)
                if decisions:
                    mechanisms.append({"arm": arm.name, "seed": seed, **decisions})
                log.append(
                    "campaign",
                    {
                        "arm": arm.name,
                        "seed": seed,
                        "execs": stats.execs_done,
                        "edges": stats.edges_found,
                        "coverage": stats.coverage_percent,
                        "crashes": len(crashes),
                        "distinct": len({c.signature for c in crashes}),
                        "decisions": decisions,
                        "wall_s": elapsed,
                    },
                )
                print(
                    f"  {arm.name:<10} seed={seed:<6} execs={stats.execs_done:<7} "
                    f"edges={stats.edges_found:<5} distinct={len({c.signature for c in crashes})} "
                    f"({elapsed}s)",
                    flush=True,
                )

    summaries = experiment.summaries(ARMS)
    notes = []
    if len(seeds) < 3:
        notes.append(
            f"only {len(seeds)} seed(s); the per-arm spread is reported but no claim of "
            "statistical significance is made"
        )
    json_path, md_path = report.write_results(
        experiment, summaries, mechanisms, out_dir=DATA_DIR, baseline="stock", extra_notes=notes
    )
    print()
    print(report.render_arm_table(summaries))
    print()
    print(f"json: {json_path}")
    print(f"md:   {md_path}")
    print(f"evidence: {log_path}")
    _cleanup_if_ok(args)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="compile the target and the scheduler library")
    build.set_defaults(func=cmd_build)

    pilot = sub.add_parser("pilot", help="short single-seed run to validate the harness")
    pilot.add_argument("--budget", type=int, default=30)
    pilot.add_argument("--seed", type=int, default=1337)
    pilot.add_argument("--keep", action="store_true", help="do not delete the WSL work tree")
    pilot.set_defaults(func=cmd_pilot)

    run = sub.add_parser("run", help="the experiment")
    run.add_argument("--name", default="fuzzlab-main")
    run.add_argument("--budget", type=int, default=120, help="seconds per campaign")
    run.add_argument("--seeds", type=int, default=3)
    run.add_argument("--seed-base", type=int, default=1337)
    run.add_argument("--arms", default="", help="comma separated; default is all")
    run.add_argument("--keep", action="store_true", help="do not delete the WSL work tree")
    run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
