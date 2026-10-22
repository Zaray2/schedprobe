"""Turn a raw AFL++ stats dump into the experiment's data and tables.

This exists because the numbers in a research document must be reproducible from the raw
output rather than typed in by whoever wrote the prose. The input is the exact text of
``grep -H -E '^(execs_done|edges_found|saved_crashes)' out/*/default/fuzzer_stats``; the output
is the JSON and markdown the document quotes.

    python scripts/fuzzlab_analyze.py docs/research/fuzzlab-data/<raw>.txt --name <experiment>

Campaigns that were killed by the external timeout are reported separately rather than
dropped: a campaign that reached 43 executions in a 90-second budget did not "score low",
it hung, and averaging it in with the others would turn a harness failure into a result.
Whatever number of executions counts as "ran to completion" is stated on the command line so
the threshold is visible instead of implied.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

#: execs_done : 12345  (with the AFL++ column padding)
_LINE = re.compile(r"^(?P<name>[^:]+):(?P<key>[a-z_]+)\s*:\s*(?P<value>\S+)$")


def parse_raw(text: str) -> dict[str, dict[str, int]]:
    """``arm-seed`` -> {key: int}. Keys are read as integers; AFL++ writes them bare."""
    campaigns: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        match = _LINE.match(line.strip())
        if not match:
            continue
        name = match.group("name")
        key = match.group("key")
        try:
            value = int(float(match.group("value")))
        except ValueError:
            continue
        campaigns.setdefault(name, {})[key] = value
    return campaigns


def split_name(name: str) -> tuple[str, str]:
    """``static-1338`` -> ``("static", "1338")``. Arm names contain no dash except the seed."""
    arm, _, seed = name.rpartition("-")
    return arm, seed


def analyse(campaigns: dict[str, dict[str, int]], *, threshold: int, budget_note: str) -> dict[str, object]:
    completed: dict[str, dict[str, dict[str, int]]] = {}
    hung: dict[str, dict[str, int]] = {}
    for name, stats in campaigns.items():
        arm, seed = split_name(name)
        if stats.get("execs_done", 0) >= threshold:
            completed.setdefault(arm, {})[seed] = stats
        else:
            hung[name] = stats

    arms: dict[str, object] = {}
    for arm, by_seed in sorted(completed.items()):
        edges = [stats.get("edges_found", 0) for stats in by_seed.values()]
        execs = [stats.get("execs_done", 0) for stats in by_seed.values()]
        crashes = [stats.get("saved_crashes", 0) for stats in by_seed.values()]
        arms[arm] = {
            "seeds": sorted(by_seed),
            "runs": len(by_seed),
            "execs_mean": round(statistics.fmean(execs), 1),
            "execs_min": min(execs),
            "execs_max": max(execs),
            "edges_mean": round(statistics.fmean(edges), 2),
            "edges_min": min(edges),
            "edges_max": max(edges),
            "edges_spread": max(edges) - min(edges),
            "edges_by_seed": dict(zip(sorted(by_seed), edges, strict=True)),
            "crashes_total": sum(crashes),
        }

    comparison = []
    baseline = arms.get("stock")
    if isinstance(baseline, dict):
        for arm, summary in arms.items():
            if not isinstance(summary, dict):
                continue
            delta = summary["edges_mean"] - baseline["edges_mean"]
            spread = max(summary["edges_spread"], baseline["edges_spread"])
            if arm == "stock":
                verdict = "baseline"
            elif len(summary["seeds"]) < 2:
                verdict = f"n={len(summary['seeds'])}: cannot judge"
            elif abs(delta) <= spread:
                verdict = "inside seed spread"
            else:
                verdict = "outside seed spread"
            comparison.append(
                {
                    "arm": arm,
                    "delta_edges_vs_stock": round(delta, 2),
                    "spread": spread,
                    "verdict": verdict,
                }
            )

    return {
        "budget_note": budget_note,
        "completion_threshold_execs": threshold,
        "arms": arms,
        "comparison": comparison,
        "campaigns_that_did_not_complete": {
            name: {"execs_done": stats.get("execs_done", 0)} for name, stats in sorted(hung.items())
        },
    }


def render(result: dict[str, object]) -> str:
    arms = result["arms"]
    assert isinstance(arms, dict)
    lines = [
        "| arm | runs | 执行次数 mean [min..max] | 边覆盖 mean [min..max] | 离散度 | 崩溃 |",
        "|---|---|---|---|---|---|",
    ]
    order = ["stock", "all", "static", "feedback", "full"]
    for arm in order:
        summary = arms.get(arm)
        if not isinstance(summary, dict):
            continue
        lines.append(
            f"| `{arm}` | {summary['runs']} | {summary['execs_mean']:.0f} "
            f"[{summary['execs_min']}..{summary['execs_max']}] "
            f"| {summary['edges_mean']:.1f} [{summary['edges_min']}..{summary['edges_max']}] "
            f"| {summary['edges_spread']} | {summary['crashes_total']} |"
        )
    lines.append("")
    lines.append("| arm | Δ边覆盖 vs `stock` | 该组离散度 | 判读 |")
    lines.append("|---|---|---|---|")
    for row in result["comparison"]:
        assert isinstance(row, dict)
        lines.append(
            f"| `{row['arm']}` | {row['delta_edges_vs_stock']:+.2f} | {row['spread']} | {row['verdict']} |"
        )
    hung = result["campaigns_that_did_not_complete"]
    if hung:
        assert isinstance(hung, dict)
        lines.append("")
        lines.append(
            f"campaigns that did not complete (fewer than "
            f"{result['completion_threshold_execs']} executions, killed by the external "
            f"timeout, excluded from the table): " + ", ".join(f"`{name}`" for name in hung)
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("raw", type=Path, help="captured fuzzer_stats fields")
    parser.add_argument("--name", required=True)
    parser.add_argument("--threshold", type=int, default=500)
    parser.add_argument(
        "--budget-note", default="90 seconds wall clock per campaign, 3 seeds, AFL++ -p explore"
    )
    parser.add_argument("--out-dir", type=Path, default=ROOT / "docs" / "research" / "fuzzlab-data")
    args = parser.parse_args()

    campaigns = parse_raw(args.raw.read_text(encoding="utf-8"))
    result = analyse(campaigns, threshold=args.threshold, budget_note=args.budget_note)
    table = render(result)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / f"{args.name}.json"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path = args.out_dir / f"{args.name}.md"
    md_path.write_text(f"# {args.name}\n\n{table}\n", encoding="utf-8")
    print(table)
    print()
    print(f"json: {json_path}")
    print(f"md:   {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
