"""Render an experiment as machine-readable data and as a table a human can argue with.

The rule this module follows: every number in the human report is a number that is also in
the JSON, and nothing is computed at render time that was not computed at measurement time.
A report that recomputes its own statistics is a report whose two forms can disagree, and the
prose will be the one that gets quoted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import ArmSummary, Experiment


def _cell(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.1f}" if abs(value) >= 10 else f"{value:.3f}"
    return str(value)


def render_arm_table(summaries: list[ArmSummary]) -> str:
    """One row per arm: budget spent, coverage reached, distinct defects found."""
    if not summaries:
        return "(no campaigns)"
    header = (
        f"{'arm':<10} {'runs':>4} {'execs(mean)':>11} {'execs[min..max]':>17} "
        f"{'edges(mean)':>12} {'edges[min..max]':>16} {'crashes':>8} {'distinct':>9}"
    )
    lines = [header, "-" * len(header)]
    for summary in summaries:
        lines.append(
            f"{summary.arm:<10} {summary.runs:>4} {summary.execs_mean:>11.0f} "
            f"{f'{summary.execs_min}..{summary.execs_max}':>17} "
            f"{summary.edges_mean:>12.1f} "
            f"{f'{summary.edges_min}..{summary.edges_max}':>16} "
            f"{summary.crashes_total:>8} {summary.unique_crashes:>9}"
        )
    return "\n".join(lines)


def render_comparison(summaries: list[ArmSummary], *, baseline: str = "stock") -> str:
    """Signed deltas against a baseline, with the seed spread stated next to each number.

    The spread is printed because a delta smaller than the spread is not a result. Saying so
    in the table is cheaper than saying it in prose, and harder to skip over.
    """
    by_name = {summary.arm: summary for summary in summaries}
    base = by_name.get(baseline)
    if base is None:
        return f"(baseline {baseline!r} did not run)"
    lines = [
        "deltas are against the baseline; `spread` is that arm's own max-min across seeds,",
        "so a delta inside the spread is not evidence of anything",
        "",
        f"{'arm':<10} {'edges':>8} {'edge_delta':>11} {'spread':>7} "
        f"{'distinct_defects':>17} {'verdict':>26}",
        "-" * 84,
    ]
    for summary in summaries:
        delta = summary.edges_mean - base.edges_mean
        decisive = abs(delta) > max(summary.edges_spread, base.edges_spread)
        if summary.arm == baseline:
            verdict = "baseline"
        elif not decisive:
            verdict = "inside seed spread"
        elif delta > 0:
            verdict = "better (outside spread)"
        else:
            verdict = "worse (outside spread)"
        lines.append(
            f"{summary.arm:<10} {summary.edges_mean:>8.1f} {delta:>+11.1f} "
            f"{summary.edges_spread:>7} {summary.unique_crashes:>17} {verdict:>26}"
        )
    return "\n".join(lines)


def render_mechanism(mechanisms: list[dict[str, Any]]) -> str:
    """Show that the policy actually did something, not only that a number moved."""
    if not mechanisms:
        return "(no plugin decision logs)"
    lines = [
        f"{'arm':<10} {'decisions':>10} {'admitted':>9} {'skipped':>8} "
        f"{'admit_ratio':>12} {'score_mean':>11}",
        "-" * 66,
    ]
    for row in mechanisms:
        lines.append(
            f"{row.get('arm', ''):<10} {row.get('decisions', 0):>10} "
            f"{row.get('admitted', 0):>9} {row.get('skipped', 0):>8} "
            f"{row.get('admit_ratio', 0.0):>12.3f} {row.get('score_mean', 0.0):>11.3f}"
        )
    return "\n".join(lines)


def render_experiment(
    experiment: Experiment,
    summaries: list[ArmSummary],
    mechanisms: list[dict[str, Any]],
    *,
    baseline: str = "stock",
    extra_notes: list[str] | None = None,
) -> str:
    """The whole human report for one experiment."""
    parts = [
        f"# {experiment.name}",
        "",
        f"- target: {experiment.target}",
        f"- budget: {experiment.budget_kind} = {experiment.budget_limit} per campaign",
        f"- seeds: {', '.join(str(seed) for seed in experiment.seeds)}",
        f"- campaigns: {len(experiment.results)}",
        "",
        "## Per-arm results",
        "",
        "```",
        render_arm_table(summaries),
        "```",
        "",
        "## Comparison",
        "",
        "```",
        render_comparison(summaries, baseline=baseline),
        "```",
        "",
        "## Scheduler mechanism",
        "",
        "A policy that moved a number without changing the admission pattern moved it by",
        "accident. These are the decisions the plugin actually made:",
        "",
        "```",
        render_mechanism(mechanisms),
        "```",
    ]
    if extra_notes:
        parts += ["", "## Notes", ""] + [f"- {note}" for note in extra_notes]
    parts += [
        "",
        "## Environment",
        "",
        "```",
        json.dumps(experiment.environment, indent=2, sort_keys=True),
        "```",
    ]
    return "\n".join(parts) + "\n"


def write_results(  # noqa: PLR0913 - the writer takes the report's parts verbatim
    experiment: Experiment,
    summaries: list[ArmSummary],
    mechanisms: list[dict[str, Any]],
    *,
    out_dir: Path,
    baseline: str = "stock",
    extra_notes: list[str] | None = None,
) -> tuple[Path, Path]:
    """Write the JSON and the markdown side by side. Returns ``(json_path, md_path)``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = experiment.to_dict()
    payload["summaries"] = [summary.to_dict() for summary in summaries]
    payload["mechanisms"] = mechanisms
    payload["baseline"] = baseline
    json_path = out_dir / f"{experiment.name}.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path = out_dir / f"{experiment.name}.md"
    md_path.write_text(
        render_experiment(experiment, summaries, mechanisms, baseline=baseline, extra_notes=extra_notes),
        encoding="utf-8",
    )
    return json_path, md_path
