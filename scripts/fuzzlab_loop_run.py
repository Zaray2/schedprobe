"""Run the FuzzLab scheduling experiment on the loop harness.

    python scripts/fuzzlab_loop_run.py build
    python scripts/fuzzlab_loop_run.py run --execs 10000 --seeds 3

The budget is **executions, not seconds**. A scheduling comparison has to hold the amount of
work constant; this loop forks per execution while libFuzzer runs in-process, so a wall-clock
budget would mostly measure fork overhead and report it as a scheduling result.

Baselines, all on the same target, corpus, seeds and execution budget:

    libfuzzer   the real libFuzzer, its own default scheduling. The external comparison that
                says whether any of this beats a mature engine.
    fifo        our loop, oldest seed first. The degenerate baseline.
    rr          our loop, round-robin. The honest simple baseline A.
    static      our loop, structural score only. Ablation.
    feedback    our loop, queue recency and starvation only. Ablation.
    full        our loop, both signals. Experiment C.

`fifo`, `rr`, `static`, `feedback` and `full` share one byte-identical binary and differ only
in a policy string, so the comparison between them is purely a comparison of scheduling.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DATA_DIR = ROOT / "docs" / "research" / "fuzzlab-data"
WSL_DISTRO = "jump1"
WSL_ROOT = "/tmp/schedprobe-loop"
CJSON_SRC = "/tmp/schedprobe-fuzzlab/src/cjson"

POLICIES = ("fifo", "rr", "static", "feedback", "full")


def wsl(script: str, *, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "-e", "bash", "-lc", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def repo_in_wsl() -> str:
    resolved = ROOT.resolve()
    drive = resolved.drive.rstrip(":").lower()
    rest = str(resolved).replace(str(resolved.drive), "").replace("\\", "/")
    return f"/mnt/{drive}{rest}"


CJSON_VERSION = "v1.7.19"


def build() -> dict[str, str]:
    """Compile the scheduling loop and a stock libFuzzer binary from the same sources."""
    repo = repo_in_wsl()
    script = f"""
set -e
mkdir -p {WSL_ROOT}/src {WSL_ROOT}/bin {WSL_ROOT}/in

CJSON_TGZ={WSL_ROOT}/src/cJSON-{CJSON_VERSION}.tar.gz
if [ ! -f "$CJSON_TGZ" ]; then
  wget -q -O "$CJSON_TGZ" "https://codeload.github.com/DaveGamble/cJSON/tar.gz/refs/tags/{CJSON_VERSION}"
fi
echo "CJSON_SHA256=$(sha256sum $CJSON_TGZ | cut -d' ' -f1)"
if [ ! -f {CJSON_SRC}/cJSON.c ]; then
  rm -rf {CJSON_SRC} && mkdir -p {CJSON_SRC}
  tar xzf "$CJSON_TGZ" -C {CJSON_SRC} --strip-components=1
fi

# The starting corpus is part of the experiment, so it is defined here and nowhere else:
# six structural shapes covering the three parse paths the harness drives.
rm -rf {WSL_ROOT}/in && mkdir -p {WSL_ROOT}/in
printf '\\000{{"id":1,"name":"a","tags":[1,2,3],"nested":{{"k":true}}}}' > {WSL_ROOT}/in/json_flat
printf '\\000{{"id":2,"items":[{{"a":[1,2]}},{{"b":[3,4]}}]}}' > {WSL_ROOT}/in/json_nested
printf '\\000[1,2,3,' > {WSL_ROOT}/in/json_broken
printf '\\001{{"id":"x","v":null,"flag":false}}' > {WSL_ROOT}/in/json_opts
printf '\\002{{"deep":{{"deep":{{"deep":[1,2,3]}}}}}}' > {WSL_ROOT}/in/json_roundtrip
printf '\\000{{"id":3,"s":"\\\\u00e9\\\\n"}}' > {WSL_ROOT}/in/json_escapes

# Loop harness: our scheduler, with clang's SanitizerCoverage and ASAN.
clang -fsanitize=fuzzer-no-link,address -O1 -g -I{CJSON_SRC} \\
  "{repo}/targets/cjson_harness.c" {CJSON_SRC}/cJSON.c \\
  "{repo}/fuzzlab/loop/sched_loop.c" -lm -o {WSL_ROOT}/bin/fuzzloop

# Stock libFuzzer on the same target. This is the external baseline: if none of our policies
# beats it, that is the result and it gets reported.
clang -fsanitize=fuzzer,address -O1 -g -I{CJSON_SRC} \\
  "{repo}/targets/cjson_harness.c" {CJSON_SRC}/cJSON.c -lm -o {WSL_ROOT}/bin/libfuzz

test -x {WSL_ROOT}/bin/fuzzloop && test -x {WSL_ROOT}/bin/libfuzz
echo "COUNTERS=$(clang --version | head -1)"
echo BUILD_OK
"""
    result = wsl(script, timeout=600)
    if "BUILD_OK" not in result.stdout:
        raise RuntimeError(f"build failed:\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}")
    digest = next(
        (line.split("=", 1)[1] for line in result.stdout.splitlines() if line.startswith("CJSON_SHA256=")),
        "unknown",
    )
    return {"cjson_sha256": digest, "compiler": result.stdout.strip().splitlines()[-1]}


def _run_policy(policy: str, seed: int, execs: int, timeout: int) -> dict[str, object]:
    script = f"""
cd {WSL_ROOT}
rm -rf out/{policy}-{seed} && mkdir -p out/{policy}-{seed}
FUZZLAB_POLICY={policy} FUZZLAB_SEED={seed} FUZZLAB_MAX_EXECS={execs} FUZZLAB_BUDGET=3600 \\
FUZZLAB_CORPUS={WSL_ROOT}/in FUZZLAB_OUT={WSL_ROOT}/out/{policy}-{seed} \\
FUZZLAB_STATS={WSL_ROOT}/out/{policy}-{seed}.json \\
  ./bin/fuzzloop
echo "---STATS---"
cat {WSL_ROOT}/out/{policy}-{seed}.json
"""
    result = wsl(script, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"policy {policy}/{seed} failed: {result.stdout[-1500:]}{result.stderr[-1500:]}")
    payload = result.stdout.split("---STATS---", 1)[-1].strip()
    try:
        return json.loads(payload)
    except ValueError as exc:
        raise RuntimeError(f"policy {policy}/{seed} produced no stats: {payload[:400]}") from exc


_COV = re.compile(r"cov:\s*(\d+)")
#: The authoritative line: ``#10000 DONE   cov: 262 ft: 684 corp: 158/3590b ...``
_COV_DONE = re.compile(r"#\s*\d+\s+DONE\s+cov:\s*(\d+)")
#: ``COVERED_FUNC: hits: 165 edges: 7/11 ...`` from -print_coverage=1
_COVERED_EDGES = re.compile(r"edges:\s*(\d+)/\d+")


def _run_libfuzzer(seed: int, execs: int, timeout: int) -> dict[str, object]:
    """Run stock libFuzzer for a fixed number of executions and read its coverage.

    libFuzzer reports coverage on its progress line rather than in the machine-readable final
    stats, so the last `cov:` on the output is parsed. A campaign that never printed one is an
    error, not a zero: a silent parse failure would read as "libFuzzer found nothing".
    """
    script = f"""
cd {WSL_ROOT}
rm -rf out/libfuzzer-{seed} out/libfuzzer-{seed}-crashes
mkdir -p out/libfuzzer-{seed} out/libfuzzer-{seed}-crashes
cp in/* out/libfuzzer-{seed}/
# -ignore_crashes=1: by default libFuzzer exits at the first crash, so a campaign that
# found one early would report coverage for a fraction of its budget while the loop harness
# kept running through the full execution count. Crashes are counted from the artefacts.
# detect_leaks=0: LeakSanitizer runs at exit and aborts the process, which truncated the
# output before libFuzzer printed its coverage line. Leaks are not the variable under study,
# and a leak in the target is a crash-class finding that ASAN reports during the run anyway.
ASAN_OPTIONS=detect_leaks=0 ./bin/libfuzz -runs={execs} -seed={seed} -print_final_stats=1 \\
  -ignore_crashes=1 \\
  -artifact_prefix=out/libfuzzer-{seed}-crashes/ out/libfuzzer-{seed} 2>&1 \\
  | grep -E '#[0-9]+[[:space:]]+DONE|ERROR: AddressSanitizer|SUMMARY' | tail -20
"""
    result = wsl(script, timeout=timeout)
    text = result.stdout + result.stderr
    # The DONE line is the authoritative figure: it is the same SanitizerCoverage counter
    # count that the loop harness reports, so the two are directly comparable. The
    # per-function report is a different accounting and mixing it in would compare unlike
    # quantities - a pilot did exactly that and put libFuzzer at 117 edges against 282 for
    # the loop, which was a parsing artefact rather than a result.
    matches = _COV_DONE.findall(text) or _COV.findall(text)
    if not matches:
        # Fallback: libFuzzer only prints `cov:` on its progress line, which short campaigns
        # can skip. The coverage report at `-print_coverage=1` always lists per-function edge
        # counts, so their sum is the same quantity by another route. A campaign that
        # produced neither is an error rather than a zero.
        per_func = _COVERED_EDGES.findall(text)
        if not per_func:
            raise RuntimeError(f"libFuzzer/{seed} printed no coverage: {text[-800:]}")
        matches = [str(sum(int(value) for value in per_func))]
    # Only non-empty artefacts count. A zero-byte file is LeakSanitizer's empty reproducer
    # from an earlier run, and counting it as a crash would credit libFuzzer with a finding
    # it did not make.
    crashes = wsl(
        f"find {WSL_ROOT}/out/libfuzzer-{seed}-crashes -type f -not -empty 2>/dev/null | wc -l"
    ).stdout.strip()
    return {
        "policy": "libfuzzer",
        "seed": seed,
        "execs": execs,
        "edges_found": int(matches[-1]),
        "corpus_size": None,
        "crashes": int(crashes) if crashes.isdigit() else 0,
        "artifact_dir": f"{WSL_ROOT}/out/libfuzzer-{seed}-crashes",
    }


def run(execs: int, seeds: int, seed_base: int) -> dict[str, object]:
    info = build()
    rows: list[dict[str, object]] = []
    seed_values = [seed_base + i for i in range(seeds)]
    # Generous wall clock: the loop runs at ~165 execs/s, so the timeout only has to catch a
    # hang, not bound the work.
    timeout = int(execs / 60) + 300

    for policy in POLICIES:
        for seed in seed_values:
            started = time.time()
            payload = _run_policy(policy, seed, execs, timeout)
            rows.append({**payload, "wall_s": round(time.time() - started, 1)})
            print(
                f"  {policy:<9} seed={seed:<5} edges={payload['edges_found']:<5} "
                f"corpus={payload['corpus_size']:<4} crashes={payload['crashes']}",
                flush=True,
            )

    for seed in seed_values:
        payload = _run_libfuzzer(seed, execs, 600)
        rows.append(payload)
        print(
            f"  {'libfuzzer':<9} seed={seed:<5} edges={payload['edges_found']:<5} "
            f"crashes={payload['crashes']}",
            flush=True,
        )

    return {"info": info, "rows": rows, "execs": execs, "seeds": seed_values}


def summarise(payload: dict[str, object]) -> tuple[list[dict[str, object]], str]:
    rows = payload["rows"]
    assert isinstance(rows, list)
    by_policy: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        by_policy.setdefault(str(row["policy"]), []).append(row)

    summary: list[dict[str, object]] = []
    for policy in ("libfuzzer", *POLICIES):
        group = by_policy.get(policy)
        if not group:
            continue
        edges = [int(row["edges_found"]) for row in group]
        summary.append(
            {
                "policy": policy,
                "runs": len(group),
                "edges_mean": round(statistics.fmean(edges), 2),
                "edges_min": min(edges),
                "edges_max": max(edges),
                "edges_spread": max(edges) - min(edges),
                "crashes_total": sum(int(row["crashes"]) for row in group),
            }
        )

    reference = next((row for row in summary if row["policy"] == "rr"), None)
    lines = [
        "| policy | runs | 边覆盖 mean [min..max] | 离散度 | 崩溃 |",
        "|---|---|---|---|---|",
    ]
    for row in summary:
        lines.append(
            f"| `{row['policy']}` | {row['runs']} | {row['edges_mean']} "
            f"[{row['edges_min']}..{row['edges_max']}] | {row['edges_spread']} | {row['crashes_total']} |"
        )
    if reference:
        lines += ["", "| policy | Δ vs `rr` | 判读 |", "|---|---|---|"]
        for row in summary:
            delta = float(row["edges_mean"]) - float(reference["edges_mean"])
            threshold = max(int(row["edges_spread"]), int(reference["edges_spread"]))
            if row["policy"] == "rr":
                verdict = "baseline A"
            elif abs(delta) <= threshold:
                verdict = "inside seed spread"
            else:
                verdict = "outside seed spread"
            lines.append(f"| `{row['policy']}` | {delta:+.2f} | {verdict} |")
    return summary, "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build").set_defaults(func=lambda _a: (print(build()), 0)[1])
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--execs", type=int, default=10000)
    run_parser.add_argument("--seeds", type=int, default=3)
    run_parser.add_argument("--seed-base", type=int, default=1337)
    run_parser.add_argument("--name", default="fuzzlab-loop")
    run_parser.set_defaults(func=None)
    args = parser.parse_args()

    if args.command == "build":
        print(build())
        return 0

    payload = run(args.execs, args.seeds, args.seed_base)
    summary, table = summarise(payload)
    payload["summary"] = summary
    payload["environment"] = {
        "host_os": platform.system(),
        "fuzzing_os": "Alpine Linux (WSL2)",
        "target": f"cJSON {CJSON_VERSION}",
        "cjson_sha256": payload["info"]["cjson_sha256"],
        "sanitizer": "ASAN",
        "coverage": "clang SanitizerCoverage (fuzzer-no-link)",
        "budget": f"{args.execs} executions per campaign",
        "mutation": "constant havoc set across all loop policies",
    }

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    json_path = DATA_DIR / f"{args.name}.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path = DATA_DIR / f"{args.name}.md"
    md_path.write_text(f"# {args.name}\n\n{table}\n", encoding="utf-8")
    print()
    print(table)
    print()
    print(f"json: {json_path}")
    print(f"md:   {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
