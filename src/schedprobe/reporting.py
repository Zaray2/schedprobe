"""Console and file rendering.

Rules this module follows:

* **No invented data.** Every number printed comes from a ``ScanRun``, an evidence
  log or a benchmark result object. If a value is unknown, it prints as ``-``.
* **Honest truncation.** When output is capped, the footer says how many rows were
  hidden instead of quietly dropping them.
* **Terminal-safe.** Host strings are operator-supplied and bounded by the target
  validator; labels and notes are sanitized before printing so a crafted label
  cannot inject control characters into a terminal or a CI log.
"""

from __future__ import annotations

import csv
import io
import json
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .models import PortState, ProbeResult
from .util import clamp

__all__ = [
    "render_benchmark_table",
    "render_diff",
    "render_replay",
    "render_run_table",
    "render_summary",
    "render_table",
    "render_verify",
    "sanitize",
    "write_results",
]

_SAFE_VIEW = set(range(0x20, 0x7F))


def sanitize(text: str, limit: int = 160) -> str:
    """Strip control characters and cap length, preserving printable Unicode.

    The first version of this function only allowed ASCII, which silently turned
    every non-Latin label into ``?`` - a bug that mattered immediately on a zh-CN
    host. The rule now: allow anything that Unicode calls printable, drop C0/C1
    controls (which include ``\\r``, ``\\n`` and ``\\x1b``, i.e. the characters that
    can hijack a terminal), drop bidi/format characters, and cap the length.
    """
    out: list[str] = []
    for ch in str(text):
        if ch in "\t":
            out.append(" ")
            continue
        # Cc/Cf cover the control and format ranges that can hijack a terminal; Zl/Zp
        # (U+2028/2029) are newline look-alikes that some terminals treat as breaks.
        if unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}:
            continue
        out.append(ch)
    cleaned = "".join(out)
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def _pad(value: Any, width: int, align: str = "<") -> str:
    text = sanitize("" if value is None else str(value), limit=max(width, 8))
    return f"{text:{align}{width}}" if len(text) <= width else text[:width]


def render_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Fixed-width ASCII table with no ANSI escapes, safe to paste into a report."""
    if not headers:
        return ""
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(sanitize(cell)))
    rule = "-+-".join("-" * width for width in widths)
    lines = [
        " | ".join(_pad(h, widths[i]) for i, h in enumerate(headers)),
        rule,
    ]
    for row in rows:
        lines.append(" | ".join(_pad(cell, widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def render_summary(summary: Mapping[str, Any], *, title: str = "run summary") -> str:
    """Render a :class:`~schedprobe.engine.RunSummary` dict as aligned key/value lines."""
    order = [
        "planner",
        "backend",
        "cost_unit",
        "pairs_total",
        "dispatched",
        "budget",
        "cost_spent",
        "budget_used_ratio",
        "cost_of_filtered",
        "waste_ratio",
        "open",
        "closed",
        "filtered",
        "undetermined",
        "confirms",
        "pruned_segments",
        "elapsed_s",
        "time_to_first_open_s",
        "first_open",
    ]
    lines = [f"[{sanitize(title)}]"]
    label_width = max(len(key) for key in order if key in summary) if summary else 0
    for key in order:
        if key not in summary:
            continue
        value = summary[key]
        if key.endswith("_ratio"):
            value = f"{float(value):.1%}"
        elif key == "elapsed_s":
            value = f"{float(value):.4f}s"
        elif key == "time_to_first_open_s":
            value = "-" if value is None else f"{float(value):.4f}s"
        elif key == "first_open":
            value = "-" if value is None else f"{value[0]}:{value[1]}"
        lines.append(f"  {key:<{label_width}} : {sanitize(value, 120)}")
    return "\n".join(lines)


def render_run_table(
    results: Mapping[tuple[str, int], ProbeResult],
    *,
    display_host: Callable[[str], str] | None = None,
    include_closed: bool = False,
    max_rows: int = 200,
) -> str:
    """Tabular view of a run's per-port results.

    ``display_host`` is an optional callable so the caller can apply the run's
    redaction setting; this module never decides policy.
    """
    selected: list[tuple[str, int, ProbeResult]] = []
    for (host, port), result in sorted(results.items()):
        if result.state is PortState.CLOSED and not include_closed:
            continue
        selected.append((host, port, result))
    selected.sort(key=lambda item: (item[2].state.value, item[0], item[1]))
    shown = selected[:max_rows] if max_rows > 0 else selected
    rows: list[list[Any]] = []
    for host, port, result in shown:
        label = display_host(host) if callable(display_host) else host
        rows.append(
            [
                label,
                port,
                result.state.value,
                result.verdict.value,
                "yes" if result.attempt > 1 else "no",
                f"{result.confidence:.2f}",
                result.cost_units,
                sanitize(result.detail, 40),
            ]
        )
    table = render_table(["host", "port", "state", "verdict", "confirm", "conf", "cost", "detail"], rows)
    hidden = len(selected) - len(shown)
    footer = []
    if hidden > 0:
        footer.append(f"... {hidden} more rows hidden (use --max-rows 0 to show all)")
    if not include_closed:
        closed = sum(1 for result in results.values() if result.state is PortState.CLOSED)
        footer.append(f"({closed} closed ports omitted; pass --include-closed to list them)")
    return "\n".join([table, *footer]) if footer else table


def render_verify(status: Mapping[str, Any]) -> str:
    head = "OK  " if status.get("ok") else "FAIL"
    lines = [
        f"{head} evidence chain: {sanitize(status.get('path', ''), 120)}",
        f"      records      : {status.get('records')}",
        f"      run_id       : {sanitize(status.get('run_id', ''), 60)}",
        f"      chain head   : {sanitize(status.get('head', ''), 80)}",
    ]
    if status.get("kinds"):
        pairs = ", ".join(f"{k}={v}" for k, v in sorted(status["kinds"].items()))
        lines.append(f"      record kinds : {sanitize(pairs, 160)}")
    if not status.get("ok"):
        lines.append(f"      first bad seq: {status.get('first_bad_seq')}")
        lines.append(f"      reason       : {sanitize(status.get('reason', ''), 160)}")
    if status.get("manifest_checked"):
        lines.append(f"      manifest     : {sanitize(str(status['manifest_checked']), 160)}")
    return "\n".join(lines)


def render_replay(report: Mapping[str, Any]) -> str:
    head = "OK  " if report.get("ok") else "FAIL"
    lines = [
        f"{head} replay: {sanitize(report.get('run_id', ''), 60)} (planner={report.get('planner')})",
        f"      observations  : {report.get('observations')}",
        f"      decisions     : {report.get('decisions_checked')}",
        f"      rank updates  : {report.get('rank_updates_checked')}",
        f"      live changes  : {report.get('live_changes_checked')}",
        f"      frontier match: {report.get('frontier_match')}",
        f"      segments match: {report.get('segments_match')}",
    ]
    divergences = report.get("divergences") or []
    if divergences:
        lines.append(f"      divergences   : {len(divergences)}")
        for item in divergences[:10]:
            lines.append(f"        - {sanitize(item, 200)}")
        if len(divergences) > 10:
            lines.append(f"        ... {len(divergences) - 10} more")
    return "\n".join(lines)


def render_benchmark_table(payload: Mapping[str, Any]) -> str:
    """Render the benchmark comparison returned by ``bench/harness.py``."""
    rows: list[list[Any]] = []
    for item in payload.get("runs", []):
        rows.append(
            [
                item["planner"],
                item["open_found"],
                item["open_total"],
                f"{item['recall']:.1%}",
                f"{item['precision']:.1%}",
                item["dispatched"],
                item["cost_spent"],
                item["cost_of_filtered"],
                f"{item['waste_ratio']:.1%}",
                item.get("time_to_first_open_cost", "-"),
            ]
        )
    table = render_table(
        [
            "planner",
            "open",
            "truth",
            "recall",
            "precision",
            "dispatched",
            "cost",
            "cost_filtered",
            "waste",
            "ttfo_cost",
        ],
        rows,
    )
    return "\n".join(
        [
            f"[benchmark] scenario={payload.get('scenario')} seed={payload.get('seed')} "
            f"budget={payload.get('budget')} hosts={payload.get('hosts')} ports={payload.get('ports')}",
            table,
            f"baseline(planner=fixed): {json.dumps(payload.get('delta_vs_fixed', {}), sort_keys=True)}",
        ]
    )


def render_diff(payload: Mapping[str, Any]) -> str:
    lines = [
        f"[diff] {sanitize(payload.get('left', ''), 40)} -> {sanitize(payload.get('right', ''), 40)}",
        f"  new         : {len(payload.get('new', []))}",
        f"  disappeared : {len(payload.get('disappeared', []))}",
        f"  changed     : {len(payload.get('changed', []))}",
        f"  unstable    : {len(payload.get('unstable', []))}",
    ]
    for key in ("new", "disappeared"):
        for item in payload.get(key, [])[:20]:
            lines.append(f"    {key[:4]:<4} {item}")
    for item in payload.get("changed", [])[:20]:
        lines.append(f"    chg  {item['host']}:{item['port']} {item['from']} -> {item['to']}")
    if payload.get("note"):
        lines.append(f"  note        : {sanitize(payload['note'], 200)}")
    return "\n".join(lines)


def write_results(  # noqa: PLR0913 - output shaping options, all keyword-only
    path: str | Path,
    results: Mapping[tuple[str, int], ProbeResult],
    *,
    fmt: str = "json",
    display_host: Callable[[str], str] | None = None,
    include_closed: bool = True,
    max_results: int = 0,
) -> Path:
    """Write results as json/jsonl/csv. Returns the path written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for (host, _port), result in sorted(results.items()):
        if result.state is PortState.CLOSED and not include_closed:
            continue
        record = result.to_dict()
        record["host"] = display_host(host) if callable(display_host) else host
        rows.append(record)
    if max_results > 0:
        rows = rows[:max_results]

    if fmt == "json":
        target.write_text(
            json.dumps({"count": len(rows), "results": rows}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif fmt == "jsonl":
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    elif fmt == "csv":
        buffer = io.StringIO()
        fieldnames = ["host", "port", "state", "verdict", "cost_units", "confidence", "attempt", "detail"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        target.write_text(buffer.getvalue(), encoding="utf-8", newline="\n")
    else:  # pragma: no cover - guarded by config validation
        raise ValueError(f"unsupported format: {fmt}")
    return target


def rate(value: Any, total: Any) -> float:
    try:
        denominator = float(total)
    except (TypeError, ValueError):
        return 0.0
    if denominator <= 0:
        return 0.0
    return clamp(float(value) / denominator, 0.0, 1.0)
