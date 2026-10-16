"""``schedprobe`` command line entry point.

Subcommands
-----------
``scan``      run a probe sweep and persist an auditable record
``demo``      end-to-end storefront demo on the deterministic simulator, no network
``bench``     run the planner comparison harness
``verify``    check the hash chain and (optionally) a run's manifest
``replay``    re-derive every scheduling decision from a log, offline
``explain``   show the decision timeline of one run
``diff``      compare two runs with anti-flap classification
``hostinfo``  measure round-trip behaviour of one host to choose timeouts
``config``    ``init`` a config file, or ``validate`` an existing one
``version``   print version and environment information

Design notes
------------
* Argument parsing is ``argparse`` with typed converters, so bad input fails with
  exit code 2 and a readable message before anything touches the network.
* Every subcommand is a function ``(args, emitter) -> int``; ``main`` never
  contains business logic, which keeps it testable through the same call path the
  shell uses.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import __version__
from ..bench import compare, default_case, environment, run_benchmark, write_results
from ..config import (
    BACKEND_KINDS,
    PLANNER_KINDS,
    ScanConfig,
    config_to_dict,
    default_config,
    load_config,
)
from ..diff import diff_runs
from ..errors import ConfigError, EvidenceError, SchedProbeError
from ..evidence import (
    MANIFEST_FILENAME,
    decision_timeline,
    reason_histogram,
    status_to_dict,
    verify_chain,
)
from ..planners import PLANNER_CLASSES
from ..replay import replay_chain
from ..reporting import (
    render_benchmark_table,
    render_diff,
    render_replay,
    render_run_table,
    render_summary,
    render_verify,
    sanitize,
)
from ..reporting import (
    write_results as write_scan_results,
)
from ..targets import COMMON_PORTS, parse_ports
from .console import (
    EXIT_EVIDENCE,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_REPLAY,
    EXIT_USAGE,
    Emitter,
    configure_stdio,
    exit_code_for,
    format_error,
    internal_traceback,
    run_async,
)

if TYPE_CHECKING:
    from ..engine import ScanRun

__all__ = ["build_parser", "dispatch", "main"]

PROG = "schedprobe"


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Budget-aware, auditable TCP probe scheduler for authorized security testing.\n"
            "Every scheduling decision is written to a hash-chained evidence log that can be "
            "verified and replayed offline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            f"  {PROG} demo                                     # no network, deterministic\n"
            f"  {PROG} scan -t 127.0.0.1 -p 80,443 --backend real\n"
            f"  {PROG} bench --scenario blackhole-segment --budget 4000\n"
            f"  {PROG} verify runs/<run-id>\n"
            f"  {PROG} replay runs/<run-id> --strict\n"
            f"  {PROG} explain runs/<run-id> --pair 10.0.20.5:80\n"
            "\nexit codes: 0 ok, 2 usage/config, 3 evidence, 4 replay divergence, 130 interrupted\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--json", action="store_true", dest="json_mode", help="machine-readable output")
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    _add_scan(subparsers)
    _add_demo(subparsers)
    _add_bench(subparsers)
    _add_verify(subparsers)
    _add_replay(subparsers)
    _add_explain(subparsers)
    _add_diff(subparsers)
    _add_hostinfo(subparsers)
    _add_config(subparsers)
    _add_version(subparsers)
    return parser


def _scan_common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "-t",
        "--target",
        action="append",
        dest="targets",
        metavar="HOST",
        help="host, hostname or CIDR (repeatable, comma separated)",
    )
    sp.add_argument(
        "-p",
        "--ports",
        metavar="SPEC",
        help=(
            "ports: '80,443', '1-1024', or a preset (top50|all). "
            f"default: top50 ({len(COMMON_PORTS)} ports)"
        ),
    )
    sp.add_argument("-c", "--config", metavar="FILE", help="TOML/JSON config file")
    sp.add_argument("--planner", choices=PLANNER_KINDS, default=None)
    sp.add_argument("--budget", type=int, metavar="UNITS", help="hard probe-cost budget")
    sp.add_argument("--seed", type=int, help="determinism seed")
    sp.add_argument("--prefix-len", type=int, help="segment prefix length for adaptive planning")
    sp.add_argument("--base-timeout", type=float, metavar="S", help="initial probe timeout")
    sp.add_argument("--max-timeout", type=float, metavar="S", help="timeout ceiling")
    sp.add_argument("--min-timeout", type=float, metavar="S", help="timeout floor")
    sp.add_argument("--concurrency", type=int)
    sp.add_argument("--rate-limit", type=float, metavar="PPS", help="probe rate ceiling, 0 = unlimited")
    sp.add_argument("--confirm-attempts", type=int, metavar="N", help="extra tries for inconclusive ports")
    sp.add_argument("--confidence-threshold", type=float, metavar="F")
    sp.add_argument("--prune-after", type=int, metavar="N", help="timeouts before a segment is pruned")
    sp.add_argument("--out-dir", metavar="DIR", help="artifact directory (default: runs)")
    sp.add_argument("--label", default="", help="short label stored in the run header")
    sp.add_argument("--notes", default="", help="free-form note stored in the run header")
    sp.add_argument(
        "--redact",
        action="store_true",
        help="pseudonymise host identifiers in the console table and in result "
        "files. NOTE: the evidence log keeps real hosts on purpose - it is "
        "the audit record and the replay verifier needs them",
    )
    sp.add_argument("--format", choices=["table", "json", "jsonl", "csv"], default="table")
    sp.add_argument("--include-closed", action="store_true")
    sp.add_argument("--max-rows", type=int, default=200, help="0 = no limit")
    sp.add_argument("--max-results", type=int, default=0, help="cap rows written to results files")
    sp.add_argument(
        "--allow-public",
        action="store_true",
        help="permit public address space; only for assets you are authorized to test",
    )
    sp.add_argument("--allow-dns", action="store_true", help="permit hostname targets")
    sp.add_argument(
        "--authorization",
        metavar="REF",
        default="",
        help="ticket/engagement reference recorded in the run header for audit",
    )
    sp.add_argument("--no-artifacts", action="store_true", help="do not write run artifacts to disk")


def _add_scan(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("scan", help="run a probe sweep against validated targets")
    _scan_common(sp)
    sp.add_argument(
        "--backend",
        choices=BACKEND_KINDS,
        default="fake",
        help="'real' performs TCP connects; 'fake' uses the simulator",
    )
    sp.add_argument("--scenario", help="simulation scenario (fake backend)")
    sp.add_argument(
        "--grab-banner",
        action="store_true",
        help="read-only banner fetch for open ports (real backend, opt-in)",
    )
    sp.set_defaults(func=cmd_scan)


def _add_demo(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("demo", help="deterministic end-to-end demo (no network access)")
    sp.add_argument("--scenario", default="blackhole-segment")
    sp.add_argument("--budget", type=int, default=4000)
    sp.add_argument("--seed", type=int, default=1337)
    sp.add_argument("--out-dir", default="runs", metavar="DIR")
    sp.add_argument("--format", choices=["table", "json"], default="table")
    sp.set_defaults(func=cmd_demo)


def _add_bench(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("bench", help="compare planners on a deterministic scenario")
    sp.add_argument("--scenario", default="blackhole-segment")
    sp.add_argument("--budget", type=int, default=4000)
    sp.add_argument("--seed", type=int, default=1337)
    sp.add_argument(
        "--planners",
        default=",".join(("adaptive", "fixed", "random", "fixed-longtimeout")),
        help="comma-separated planner names",
    )
    sp.add_argument("--out-dir", default="runs", metavar="DIR")
    sp.add_argument("--format", choices=["table", "json"], default="table")
    sp.add_argument("--save", metavar="FILE", help="write the full result JSON here")
    sp.set_defaults(func=cmd_bench)


def _add_verify(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("verify", help="verify the evidence hash chain and manifest")
    sp.add_argument("run", help="run directory or evidence.jsonl path")
    sp.add_argument("--manifest", help="manifest.json to check against (default: alongside the log)")
    sp.add_argument("--json", action="store_true", dest="json_mode", help=argparse.SUPPRESS)
    sp.set_defaults(func=cmd_verify)


def _add_replay(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("replay", help="re-derive scheduling decisions from a log (offline)")
    sp.add_argument("run", help="run directory or evidence.jsonl path")
    sp.add_argument("--strict", action="store_true", help="exit non-zero on any divergence")
    sp.set_defaults(func=cmd_replay)


def _add_explain(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("explain", help="show why each probe was scheduled")
    sp.add_argument("run", help="run directory or evidence.jsonl path")
    sp.add_argument("--pair", metavar="HOST:PORT", help="focus on one pair")
    sp.add_argument("--top", type=int, default=25, help="rows to show (0 = all)")
    sp.add_argument("--reasons", action="store_true", help="print only the reason histogram")
    sp.set_defaults(func=cmd_explain)


def _add_diff(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("diff", help="compare two runs with anti-flap classification")
    sp.add_argument("left", help="older run directory")
    sp.add_argument("right", help="newer run directory")
    sp.add_argument("--save", metavar="FILE", help="write the diff JSON here")
    sp.set_defaults(func=cmd_diff)


def _add_hostinfo(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("hostinfo", help="measure round-trip behaviour to pick timeouts")
    sp.add_argument("-t", "--target", required=True, metavar="HOST")
    sp.add_argument("-p", "--ports", default="80,443", metavar="SPEC")
    sp.add_argument("--samples", type=int, default=3, help="probe rounds per port")
    sp.add_argument("--timeout", type=float, default=1.0, metavar="S")
    sp.add_argument("--allow-public", action="store_true")
    sp.add_argument("--out-dir", default="runs", metavar="DIR")
    sp.set_defaults(func=cmd_hostinfo)


def _add_config(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("config", help="create or validate configuration files")
    nested = sp.add_subparsers(dest="config_command", metavar="<action>")
    init = nested.add_parser("init", help="write an example config file")
    init.add_argument("path", nargs="?", default="schedprobe.toml")
    init.add_argument("--force", action="store_true")
    validate = nested.add_parser("validate", help="validate a config file")
    validate.add_argument("path")
    show = nested.add_parser("show", help="print the effective default configuration")
    for child in (init, validate, show):
        child.set_defaults(func=cmd_config)
    sp.set_defaults(func=cmd_config)


def _add_version(sub: argparse._SubParsersAction) -> None:
    sp = sub.add_parser("version", help="print version information")
    sp.set_defaults(func=cmd_version)


# ------------------------------------------------------------------------- helpers
def _resolve_evidence_path(run: str) -> Path:
    path = Path(run)
    if path.is_dir():
        candidate = path / "evidence.jsonl"
        if not candidate.is_file():
            raise EvidenceError("directory has no evidence.jsonl", path=str(path))
        return candidate
    if path.suffix == ".jsonl" or path.is_file():
        if not path.is_file():
            raise EvidenceError("evidence log not found", path=str(path))
        return path
    raise EvidenceError("provide a run directory or an evidence.jsonl file", path=str(run))


def _config_from_args(args: argparse.Namespace, *, default_backend: str = "fake") -> ScanConfig:
    overrides: dict[str, Any] = {}
    if getattr(args, "planner", None):
        overrides["planner.kind"] = args.planner
    if getattr(args, "budget", None) is not None:
        overrides["planner.cost_budget"] = args.budget
    if getattr(args, "seed", None) is not None:
        overrides["planner.seed"] = args.seed
    if getattr(args, "prefix_len", None) is not None:
        overrides["planner.prefix_len"] = args.prefix_len
    if getattr(args, "confirm_attempts", None) is not None:
        overrides["planner.confirm_min_attempts"] = args.confirm_attempts
    if getattr(args, "confidence_threshold", None) is not None:
        overrides["planner.confidence_threshold"] = args.confidence_threshold
    if getattr(args, "prune_after", None) is not None:
        overrides["planner.prune_after_consecutive_timeouts"] = args.prune_after
    if getattr(args, "base_timeout", None) is not None:
        overrides["network.base_timeout_s"] = args.base_timeout
    if getattr(args, "min_timeout", None) is not None:
        overrides["network.min_timeout_s"] = args.min_timeout
    if getattr(args, "max_timeout", None) is not None:
        overrides["network.max_timeout_s"] = args.max_timeout
    if getattr(args, "concurrency", None) is not None:
        overrides["network.concurrency"] = args.concurrency
    if getattr(args, "rate_limit", None) is not None:
        overrides["network.rate_limit_pps"] = args.rate_limit
    if getattr(args, "out_dir", None):
        overrides["output.out_dir"] = args.out_dir
    if getattr(args, "redact", False):
        overrides["output.redact"] = True
    if getattr(args, "format", None) in ("table", "json", "jsonl", "csv"):
        overrides["output.format"] = args.format
    if getattr(args, "allow_public", False):
        overrides["safety.allow_public"] = True
    if getattr(args, "allow_dns", False):
        overrides["safety.allow_dns"] = True

    config = load_config(getattr(args, "config", None), overrides)
    if getattr(args, "targets", None):
        config.targets = tuple(
            part.strip() for group in args.targets for part in str(group).split(",") if part.strip()
        )
    if getattr(args, "ports", None):
        config.ports = parse_ports(args.ports)
    backend = getattr(args, "backend", None) or default_backend
    config.backend = backend
    config.run_label = (getattr(args, "label", "") or "")[:120]
    notes = getattr(args, "notes", "") or ""
    if getattr(args, "authorization", ""):
        notes = (notes + f" authorization={args.authorization}").strip()
    config.notes = notes[:500]
    return config.validate()


def _emit_config_warnings(config: ScanConfig, emitter: Emitter) -> None:
    pairs = len(config.targets) * len(config.ports)
    if config.planner.cost_budget < pairs:
        emitter.warn(
            f"budget {config.planner.cost_budget} is below the {pairs} planned pairs; "
            "the sweep will stop early by design (that is the point of a budget, "
            "but raise --budget if you need full coverage)"
        )
    if config.backend == "real" and config.network.rate_limit_pps == 0:
        emitter.warn("no rate limit set; use --rate-limit to stay polite to shared infrastructure")


# ------------------------------------------------------------------------ commands
def cmd_scan(args: argparse.Namespace, emitter: Emitter) -> int:
    from ..engine import ScanEngine

    config = _config_from_args(args)
    _emit_config_warnings(config, emitter)
    if args.no_artifacts:
        config.output.out_dir = os.path.join(
            os.environ.get("TEMP", "/tmp"), f"schedprobe-scratch-{os.getpid()}"
        )
    engine = ScanEngine(
        config,
        # CLI flag wins; otherwise the config file's value (so examples are runnable
        # without repeating every option on the command line).
        scenario=getattr(args, "scenario", None) or config.scenario or None,
        out_dir=config.output.out_dir,
        grab_banner=getattr(args, "grab_banner", False),
    )
    emitter.say(
        f"[{PROG}] run {engine.run_id} planner={config.planner.kind} backend={config.backend} "
        f"targets={len(config.targets)} ports={len(config.ports)} budget={config.planner.cost_budget}"
    )
    run = run_async(engine.run())
    return _report_run(run, emitter, args)


def _report_run(run: ScanRun, emitter: Emitter, args: argparse.Namespace) -> int:
    summary = run.summary.to_dict()
    fmt = getattr(args, "format", "table")
    if emitter.json_mode or fmt == "json":
        emitter.data(
            {
                "run_id": run.run_id,
                "out_dir": str(run.out_dir),
                "summary": summary,
                "segments": run.segments,
                "chain_ok": run.chain_ok,
                "results": [
                    {**result.to_dict(), "host": run.display_host(result.host)}
                    for _, result in sorted(run.results.items())
                ],
            }
        )
    else:
        emitter.say(render_summary(summary, title=f"run {run.run_id}"))
        emitter.say("")
        emitter.say(
            render_run_table(
                run.results,
                display_host=run.display_host,
                include_closed=bool(getattr(args, "include_closed", False)),
                max_rows=int(getattr(args, "max_rows", 200)),
            ),
            force=True,
        )
    if fmt in ("json", "jsonl", "csv"):
        target = run.out_dir / f"results.{fmt}"
        write_scan_results(
            target,
            run.results,
            fmt=fmt,
            display_host=run.display_host,
            include_closed=bool(getattr(args, "include_closed", True)),
            max_results=int(getattr(args, "max_results", 0)),
        )
        emitter.say(f"results written to {target}", force=True)
    emitter.say(f"evidence: {run.evidence_path}", force=True)
    emitter.say(f"manifest: {run.manifest_path}", force=True)
    emitter.say(f"chain verified: {run.chain_ok}", force=True)
    return EXIT_OK if run.chain_ok else EXIT_EVIDENCE


def cmd_demo(args: argparse.Namespace, emitter: Emitter) -> int:
    """Run the whole story offline: scan, verify, replay, explain - all deterministic."""
    from ..backends.fake import builtin_scenarios
    from ..engine import ScanEngine

    catalog = builtin_scenarios()
    if args.scenario not in catalog:
        raise ConfigError("unknown scenario", scenario=args.scenario, known=sorted(catalog))
    config = default_config(
        targets=tuple(sorted(catalog[args.scenario].hosts)),
        ports=parse_ports("22,80,443,3306,6379,8080,8443"),
        backend="fake",
        run_label=f"demo:{args.scenario}",
        notes="deterministic demo, simulator backend, no network access",
    )
    config.planner.kind = "adaptive"
    config.planner.cost_budget = args.budget
    config.planner.seed = args.seed
    config.output.out_dir = args.out_dir
    config.validate()

    emitter.say("=== schedprobe demo (no network access, deterministic) ===")
    emitter.say(f"scenario : {args.scenario} ({catalog[args.scenario].description})")
    emitter.say(f"budget   : {args.budget} cost units, seed {args.seed}")
    engine = ScanEngine(
        config,
        out_dir=args.out_dir,
        backend=None,
        scenario=args.scenario,
        run_id=f"demo-{args.scenario}-seed{args.seed}",
    )
    run = run_async(engine.run())
    emitter.say("")
    emitter.say(render_summary(run.summary.to_dict(), title="step 1/4 scan"))
    emitter.say("")
    emitter.say(
        render_run_table(run.results, display_host=run.display_host, include_closed=False, max_rows=40),
        force=True,
    )

    status = verify_chain(run.evidence_path)
    emitter.say("")
    emitter.say(render_verify(status_to_dict(run.evidence_path, status)), force=True)

    report = replay_chain(run.evidence_path)
    emitter.say("")
    emitter.say(render_replay(report.to_dict()), force=True)

    rows = decision_timeline(run.evidence_path)
    pruned = [segment for segment in run.segments if segment["pruned"]]
    emitter.say("")
    emitter.say("[step 4/4 explain] why the sweep went where it went", force=True)
    emitter.say(f"  decisions recorded : {len(rows)}")
    emitter.say(f"  reason histogram   : {json.dumps(reason_histogram(rows), sort_keys=True)}")
    if pruned:
        for segment in pruned:
            emitter.say(
                f"  pruned segment     : {sanitize(segment['segment'])} "
                f"after {segment['planned']} probes ({sanitize(segment['prune_reason'], 80)})"
            )
    else:
        emitter.say("  pruned segment     : none (no segment looked dead within this budget)")
    emitter.say(f"  artifacts          : {run.out_dir}")
    emitter.say(
        "\nreproduce this exact run with:\n"
        f"  {PROG} demo --scenario {args.scenario} --budget {args.budget} --seed {args.seed} "
        f"--out-dir {args.out_dir}"
    )
    emitter.say(f"  {PROG} verify {run.evidence_path}")
    emitter.say(f"  {PROG} replay {run.evidence_path} --strict")
    if emitter.json_mode or args.format == "json":
        emitter.data(
            {
                "run": {
                    "run_id": run.run_id,
                    "out_dir": str(run.out_dir),
                    "summary": run.summary.to_dict(),
                    "segments": run.segments,
                },
                "verify": status_to_dict(run.evidence_path, status),
                "replay": report.to_dict(),
                "reasons": reason_histogram(rows),
            }
        )
    ok = status.ok and report.ok and run.chain_ok
    if not status.ok:
        return EXIT_EVIDENCE
    if not report.ok:
        return EXIT_REPLAY
    return EXIT_OK if ok else EXIT_INTERNAL


def cmd_bench(args: argparse.Namespace, emitter: Emitter) -> int:
    planners = tuple(part.strip() for part in args.planners.split(",") if part.strip())
    unknown = [name for name in planners if name not in PLANNER_CLASSES]
    if unknown:
        raise ConfigError("unknown planner", planners=unknown, known=sorted(PLANNER_CLASSES))
    case = default_case(args.scenario, args.budget, args.seed)
    case.planners = planners
    results = run_async(run_benchmark(case, args.out_dir))
    payload = {
        "scenario": case.scenario,
        "seed": case.seed,
        "budget": case.budget,
        "hosts": len(case.hosts),
        "ports": len(case.ports),
        "environment": environment(),
        "runs": [item.to_dict() for item in results],
        "delta_vs_fixed": compare(results, baseline="fixed"),
        "note": (
            "Comparison is between schedulers shipped in this repository, on a deterministic "
            "simulator. It is not a benchmark against any third-party scanner."
        ),
    }
    if emitter.json_mode or args.format == "json":
        emitter.data(payload)
    else:
        emitter.say(render_benchmark_table(payload), force=True)
    if args.save:
        # Honour the requested filename: the earlier version passed only the parent
        # directory and always produced ``benchmark.json``, so a caller asking for
        # ``--save results/run-7.json`` silently got a different file.
        path = write_results(args.save, payload)
        emitter.say(f"full results: {path}", force=True)
    return EXIT_OK


def cmd_verify(args: argparse.Namespace, emitter: Emitter) -> int:
    path = _resolve_evidence_path(args.run)
    status = verify_chain(path)
    payload = status_to_dict(path, status)
    manifest_path = Path(args.manifest) if args.manifest else path.parent / MANIFEST_FILENAME
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise EvidenceError(f"manifest is not readable JSON: {exc}", path=str(manifest_path)) from exc
        recorded = manifest.get("evidence_sha256")
        from ..evidence import file_digest

        actual, _ = file_digest(path)
        payload["manifest_checked"] = (
            f"{manifest_path.name}: digest matches"
            if recorded == actual
            else f"{manifest_path.name}: digest MISMATCH (recorded {recorded}, actual {actual})"
        )
        if recorded != actual:
            payload["ok"] = False
            payload["reason"] = payload.get("reason") or "manifest digest does not match the evidence log"
    elif args.manifest:
        raise EvidenceError("manifest not found", path=str(manifest_path))
    emitter.say(render_verify(payload), force=True)
    if emitter.json_mode:
        emitter.data(payload)
    return EXIT_OK if payload["ok"] else EXIT_EVIDENCE


def cmd_replay(args: argparse.Namespace, emitter: Emitter) -> int:
    path = _resolve_evidence_path(args.run)
    report = replay_chain(path)
    payload = report.to_dict()
    if emitter.json_mode:
        emitter.data(payload)
    else:
        emitter.say(render_replay(payload), force=True)
    # Without --strict, a divergence is reported but is not a failure: the log is still
    # a valid record of a run whose scheduler could not be reproduced. With --strict it
    # is a hard error, which is what CI wants.
    if report.ok:
        return EXIT_OK
    return EXIT_REPLAY if args.strict else EXIT_EVIDENCE


def cmd_explain(args: argparse.Namespace, emitter: Emitter) -> int:
    path = _resolve_evidence_path(args.run)
    rows = decision_timeline(path)
    if not rows:
        raise EvidenceError("no probe decisions in this log", path=str(path))
    histogram = reason_histogram(row.get("scheduled_reason") for row in rows)
    if args.reasons:
        emitter.say(json.dumps(histogram, indent=2, sort_keys=True), force=True)
        return EXIT_OK
    selected = rows
    if args.pair:
        if ":" not in args.pair:
            raise ConfigError("--pair must look like HOST:PORT", value=args.pair)
        host, _, port = args.pair.rpartition(":")
        try:
            wanted = int(port)
        except ValueError as exc:
            raise ConfigError("--pair port must be an integer", value=port) from exc
        selected = [
            row
            for row in rows
            if (row["host"] == host and int(row["port"]) == wanted)
            or (row.get("next_host") == host and row.get("next_port") == wanted)
        ]
        if not selected:
            raise EvidenceError("no decision for that pair in this log", pair=args.pair)
    limit = args.top if args.top and args.top > 0 else len(selected)
    refreshed = sum(1 for row in rows if row.get("plan_refreshed"))
    lines = [
        f"[explain] {path}",
        f"  probes     : {len(rows)}   decisions recorded: {len(rows)}   plan refreshes: {refreshed}",
        f"  reasons    : {json.dumps(histogram, sort_keys=True)}",
        "  note       : 'scheduled_reason'/'executed' describe the probe that ran; "
        "'next' is the decision the scheduler recorded for the following probe.",
        "",
    ]
    header = (
        f"{'#':>4} {'host':<16} {'port':>5} {'scheduled_reason':<22} {'exec(s)':>7} "
        f"{'try':>3} {'state':<12} {'conf':>5} {'cost':>6} {'spent':>7} {'live':>5} {'next':<22}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for index, row in enumerate(selected[:limit], start=1):
        lines.append(
            f"{index:>4} {sanitize(str(row['host']), 16):<16} {row['port']:>5} "
            f"{sanitize(str(row['scheduled_reason']), 22):<22} "
            f"{float(row['scheduled_timeout_s'] or 0):>7.2f} {row['attempt'] or 1:>3} "
            f"{sanitize(str(row['state']), 12):<12} {float(row['confidence'] or 0):>5.2f} "
            f"{row['cost'] or 0:>6} {row['cost_spent'] or 0:>7} {row['live_pairs'] or 0:>5} "
            f"{sanitize(str(row.get('next_reason') or '-'), 22):<22}"
        )
    if len(selected) > limit:
        lines.append(f"... {len(selected) - limit} more rows (--top 0 for all)")
    emitter.say("\n".join(lines), force=True)
    if emitter.json_mode:
        emitter.data({"rows": selected[:limit], "reasons": histogram, "total": len(rows)})
    return EXIT_OK


def cmd_diff(args: argparse.Namespace, emitter: Emitter) -> int:
    report = diff_runs(args.left, args.right)
    payload = report.to_dict()
    if emitter.json_mode:
        emitter.data(payload)
    else:
        emitter.say(
            render_diff(
                {
                    "left": report.left,
                    "right": report.right,
                    "new": [str(d) for d in report.new],
                    "disappeared": [str(d) for d in report.disappeared],
                    "changed": [d.to_dict() for d in report.changed],
                    "unstable": [str(d) for d in report.unstable],
                    "note": f"anti-flap rules {report.rules_version}",
                }
            ),
            force=True,
        )
    if args.save:
        target = Path(args.save)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        emitter.say(f"diff written to {target}", force=True)
    return EXIT_OK


def cmd_hostinfo(args: argparse.Namespace, emitter: Emitter) -> int:
    """Measure one host to choose timeouts with evidence instead of folklore."""

    from ..backends.base import ProbeRequest
    from ..backends.real import RealTcpBackend
    from ..config import NetworkConfig, SafetyConfig
    from ..targets import expand_targets, validate_targets

    safety = SafetyConfig(allow_public=bool(args.allow_public))
    hosts = expand_targets([args.target], max_hosts=1)
    validate_targets(list(hosts), safety, 1)
    ports = parse_ports(args.ports)
    config = default_config(targets=hosts, ports=ports, backend="real")
    config.network = NetworkConfig(
        concurrency=1,
        base_timeout_s=args.timeout,
        min_timeout_s=min(0.15, args.timeout),
        max_timeout_s=max(args.timeout, 0.15),
        max_attempts=1,
    )
    config.validate()
    backend = RealTcpBackend(config=config, allow=list(hosts))
    samples: list[tuple[int, float]] = []

    async def _measure() -> None:
        await backend.setup()
        for _ in range(max(1, args.samples)):
            for port in ports:
                result = await backend.probe(
                    ProbeRequest(
                        host=hosts[0], port=port, timeout_s=args.timeout, max_timeout_s=args.timeout
                    )
                )
                samples.append((port, result.cost_units / 1000.0))
                emitter.say(
                    f"  {hosts[0]}:{port} -> {result.state.value}/{result.verdict.value} "
                    f"in {result.cost_units} ms"
                )
        await backend.teardown()

    emitter.say(f"[hostinfo] {hosts[0]} ports={list(ports)} samples={args.samples}")
    run_async(_measure())
    # ``samples`` holds seconds; comparing them against milliseconds made every
    # sample look answered, so a filtered host could be reported as healthy.
    answered = [seconds for _, seconds in samples if seconds < args.timeout]
    payload: dict[str, Any] = {"target": hosts[0], "samples": len(samples)}
    if answered:
        answered.sort()
        p95 = statistics.quantiles(answered, n=20)[-1] if len(answered) >= 20 else max(answered)
        ceiling = max(3.0, p95 * 4)
        recommendation = min(ceiling, max(0.15, p95 * 3))
        payload.update(
            {
                "answered": len(answered),
                "min_s": round(min(answered), 4),
                "median_s": round(statistics.median(answered), 4),
                "p95_s": round(p95, 4),
                "recommended_base_timeout_s": round(recommendation, 3),
            }
        )
        emitter.say(
            f"  answered {len(answered)}/{len(samples)} probes; "
            f"median {statistics.median(answered) * 1000:.1f} ms, p95 {p95 * 1000:.1f} ms"
        )
        emitter.say(
            "  suggested: "
            f"--base-timeout {recommendation:.2f} --min-timeout {max(0.15, recommendation / 4):.2f} "
            f"--max-timeout {ceiling:.2f}"
        )
        emitter.say("  (the recommendation is 3x the observed p95 round trip, capped at 4x p95)")
    else:
        payload.update({"answered": 0, "recommended_base_timeout_s": None})
        emitter.say(
            "  no probe was answered; the path may be filtered. Keep a larger timeout and "
            "let the planner prune instead."
        )
    if emitter.json_mode:
        emitter.data(payload)
    return EXIT_OK


def cmd_config(args: argparse.Namespace, emitter: Emitter) -> int:
    action = getattr(args, "config_command", None)
    if action is None:
        emitter.say("usage: schedprobe config {init|validate|show} [path]", force=True)
        return EXIT_USAGE
    if action == "init":
        target = Path(args.path)
        if target.exists() and not args.force:
            raise ConfigError("refusing to overwrite an existing file; pass --force", path=str(target))
        template = _config_template()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(template, encoding="utf-8")
        emitter.say(f"wrote {target}", force=True)
        return EXIT_OK
    if action == "validate":
        config = load_config(args.path)
        config.validate()
        emitter.say(
            f"OK {args.path}: {len(config.targets)} targets, {len(config.ports)} ports, "
            f"planner={config.planner.kind}, budget={config.planner.cost_budget}",
            force=True,
        )
        if emitter.json_mode:
            emitter.data(config_to_dict(config))
        return EXIT_OK
    if action == "show":
        payload = config_to_dict(default_config())
        emitter.say(json.dumps(payload, indent=2, sort_keys=True), force=True)
        return EXIT_OK
    raise ConfigError("unknown config action", action=action)


def _config_template() -> str:
    return """# schedprobe configuration (TOML). Every key here is optional.
# Generated by `schedprobe config init`; contains no secrets and no machine-specific paths.

targets = ["127.0.0.1"]
ports = [22, 80, 443, 3306, 6379, 8080, 8443]
backend = "fake"           # "real" performs TCP connects; "fake" uses the simulator
run_label = ""
notes = ""

[planner]
kind = "adaptive"           # adaptive | fixed | random | fixed-longtimeout
seed = 1337                 # same seed + same observations => same decisions
cost_budget = 4000          # hard cap on probe cost, in backend cost units
reserved_ratio = 0.15       # budget held back for confirmation probes
prefix_len = 24             # segment size used for health-based replanning
prune_after_consecutive_timeouts = 3
prune_min_planned = 3
confirm_min_attempts = 2    # extra tries for inconclusive results
confirm_timeout_multiplier = 2.5
confidence_threshold = 0.7  # below this, a result is considered inconclusive
timeout_penalty = 1.0       # how hard a filtered segment is penalised

[network]
concurrency = 128
base_timeout_s = 0.6
min_timeout_s = 0.15
max_timeout_s = 3.0
max_attempts = 2
max_hosts = 4096
max_ports = 4096
rate_limit_pps = 0.0        # 0 = unlimited; set this on shared infrastructure
resolve_timeout_s = 2.0

[output]
out_dir = "runs"
redact = false              # true pseudonymises host identifiers in every artifact
include_closed = false
max_results = 0
format = "table"            # table | json | jsonl | csv

[safety]
allow_public = false        # only enable for assets you are authorized to test
allow_private = true
allow_loopback = true
allow_dns = true
max_span_ratio = 1.0
"""


def cmd_version(args: argparse.Namespace, emitter: Emitter) -> int:
    payload = {
        "tool": PROG,
        "version": __version__,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.system(),
        "planners": sorted(PLANNER_CLASSES),
        "backends": list(BACKEND_KINDS),
        "runtime_dependencies": [],
        "deterministic_mode_available": True,
    }
    emitter.say(json.dumps(payload, indent=2, sort_keys=True), force=True)
    return EXIT_OK


# ----------------------------------------------------------------------------- main
def dispatch(args: argparse.Namespace, emitter: Emitter) -> int:
    func = getattr(args, "func", None)
    if func is None:
        build_parser().print_help()
        return EXIT_USAGE
    return int(func(args, emitter))


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by both the console script and the test-suite."""
    from ..util import configure_logging

    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    emitter = Emitter(
        quiet=bool(getattr(args, "quiet", False)),
        json_mode=bool(getattr(args, "json_mode", False)),
    )
    configure_logging(getattr(args, "log_level", "WARNING"))
    try:
        return dispatch(args, emitter)
    except BrokenPipeError:  # pragma: no cover - piping into head/less
        with suppress(Exception):
            sys.stdout.close()
        return EXIT_OK
    except SchedProbeError as exc:
        emitter.error(format_error(exc))
        if exc.context:
            emitter.error("context: " + json.dumps(exc.context, sort_keys=True, ensure_ascii=False))
        return exit_code_for(exc)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        emitter.error("interrupted")
        return 130
    except Exception as exc:
        emitter.error("internal error: " + format_error(exc))
        print(internal_traceback(exc), file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
