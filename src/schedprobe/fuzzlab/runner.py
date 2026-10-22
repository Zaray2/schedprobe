"""Campaign execution: build once, run every arm the same way, replay every crash.

Everything in this module exists to make one property true: **the arms differ only in the
scheduler**. The binary, the target, the AFL++ flags, the seed corpus, the power schedule and
the budget are identical across arms, and the code that sets them is written once rather than
per-arm. When a comparison is implemented by copying a command line five times, the third copy
develops a typo and the resulting table looks like a finding.

The environment is WSL because that is where a real coverage-guided engine and a real
sanitizer are available on this machine. The Windows side has no C toolchain, and building one
would have been a bigger project than the one being studied.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .arms import Arm
from .dedup import CrashRecord, crash_signature
from .stats import RunStats, parse_fuzzer_stats

#: Where the WSL side builds and runs. Kept out of the repository because fuzzing writes
#: thousands of small files and /mnt/c is slow enough to change the measurement.
#: Which cJSON tag to fuzz.
#:
#: 1.7.19 is the current release and is the honest choice for a coverage comparison, but it is
#: also well-fuzzed: at the budgets this machine can afford it produced no crashes in any arm,
#: which leaves the defect metric with no signal. 1.7.17 predates the advisories fixed in
#: 1.7.18, so it produces real crashes - not injected ones - which is what makes the defect
#: half of the research question measurable.
DEFAULT_CJSON_VERSION = "1.7.19"
KNOWN_BUGGY_CJSON_VERSION = "1.7.17"

WSL_ROOT = "/tmp/schedprobe-fuzzlab"

#: AFL++ needs these on a container-like host: no cpufreq daemon, no core_pattern check.
_AFL_ENV = {
    "AFL_SKIP_CPUFREQ": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    "AFL_NO_UI": "1",
    "AFL_USE_ASAN": "1",
    "AFL_QUIET": "1",
}


@dataclass(frozen=True, slots=True)
class WslResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def tail(self, lines: int = 12) -> str:
        text = (self.stdout + "\n" + self.stderr).strip()
        return "\n".join(text.splitlines()[-lines:])


def wsl(args: list[str], *, timeout: int = 600, check: bool = False) -> WslResult:
    """Run a shell command inside the fuzzing distribution."""
    script = " && ".join(args) if len(args) > 1 else args[0]
    proc = subprocess.run(
        ["wsl", "-d", "jump1", "-e", "bash", "-lc", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    result = WslResult(proc.returncode, proc.stdout, proc.stderr)
    if check and not result.ok:
        raise RuntimeError(f"WSL command failed ({result.returncode}): {result.tail()}")
    return result


def _repo_in_wsl(repo_root: Path) -> str:
    """Translate a Windows repo path into its /mnt/... form."""
    resolved = repo_root.resolve()
    drive = resolved.drive.rstrip(":").lower()
    rest = str(resolved).replace(str(resolved.drive), "").replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def build(repo_root: Path, *, version: str = DEFAULT_CJSON_VERSION, jobs: int = 1) -> dict[str, str]:
    """Compile the instrumented target and the scheduler library.

    Returns the paths (WSL-side) of both artefacts. Raises with the compiler output on
    failure, because a build error silently downgraded to a skip would turn a broken harness
    into a passing experiment.
    """
    repo = _repo_in_wsl(repo_root)
    root = WSL_ROOT
    script = f"""
set -e
mkdir -p {root}/bin {root}/in {root}/src
cd {root}

# --- target source -------------------------------------------------------------------
#
# The first version of this build linked against the *system* cJSON package. That produced a
# fuzzer with five edges of coverage, because a prebuilt shared library carries no
# instrumentation: only the 30-line driver was visible to AFL++, so every seed looked
# identical and the scheduling policy had nothing to schedule. The warning was explicit
# ("No new instrumentation output") and the experiment would have been meaningless.
#
# So the parser is compiled from source with the same instrumenting compiler as the harness.
# The tarball is fetched once and cached; the digest is recorded so a report can say exactly
# which bytes were fuzzed.
CJSON_VER=v{version}
CJSON_TGZ={root}/src/cJSON-$CJSON_VER.tar.gz
if [ ! -f "$CJSON_TGZ" ]; then
  wget -q -O "$CJSON_TGZ" "https://codeload.github.com/DaveGamble/cJSON/tar.gz/refs/tags/$CJSON_VER"
fi
echo "CJSON_SHA256=$(sha256sum $CJSON_TGZ | cut -d' ' -f1)"
rm -rf {root}/src/cjson && mkdir -p {root}/src/cjson
tar xzf "$CJSON_TGZ" -C {root}/src/cjson --strip-components=1
test -f {root}/src/cjson/cJSON.c

# --- harness driver ------------------------------------------------------------------
cat > {root}/src/driver.c <<'DRIVER'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern int LLVMFuzzerTestOneInput(const uint8_t*, size_t);
int main(int argc, char** argv) {{
  if (argc < 2) return 0;
  FILE* f = fopen(argv[1], "rb"); if(!f) return 1;
  fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
  if (n < 0) {{ fclose(f); return 1; }}
  uint8_t* b = (uint8_t*)malloc((size_t)n ? (size_t)n : 1);
  size_t got = fread(b,1,(size_t)n,f); fclose(f);
  int r = LLVMFuzzerTestOneInput(b, got); free(b); return r;
}}
DRIVER

# --- corpus --------------------------------------------------------------------------
rm -rf in && mkdir -p in
printf '\\000{{"id":1,"name":"a","tags":[1,2,3],"nested":{{"k":true}}}}' > in/json_flat
printf '\\000{{"id":2,"items":[{{"a":[1,2]}},{{"b":[3,4]}}]}}' > in/json_nested
printf '\\000[1,2,3,' > in/json_broken
printf '\\001{{"id":"x","v":null,"flag":false}}' > in/json_opts
printf '\\002{{"deep":{{"deep":{{"deep":[1,2,3]}}}}}}' > in/json_roundtrip
printf '\\000{{"id":3,"s":"\\u00e9\\n"}}' > in/json_escapes

# --- build ---------------------------------------------------------------------------
# cJSON is compiled as a static object WITH instrumentation, so its edges are visible.
AFL_USE_ASAN=1 afl-clang-fast -O1 -g -c {root}/src/cjson/cJSON.c -I{root}/src/cjson -o bin/cJSON.o
AFL_USE_ASAN=1 afl-clang-fast -O1 -g -I{root}/src/cjson \
  "{repo}/targets/cjson_harness.c" {root}/src/driver.c bin/cJSON.o -lm -o bin/target
clang -O2 -fPIC -shared -Wall -Wextra -I"{repo}/fuzzlab/hooks" \
  "{repo}/fuzzlab/hooks/sched_hook.c" -o bin/hook.so

# --- prove the instrumentation actually sees the parser -------------------------------
# A build that links an uninstrumented parser still produces a working binary; the only
# symptom is a fuzzer that is blind, every seed looking identical. The first attempt at this
# experiment shipped exactly that: `Bitmap range : 5 to 5 bits`, because the system cJSON
# package carries no instrumentation. Measuring the edge count here turns that silent failure
# into a build error. `afl-showmap` is not shipped by Alpine's afl++ package, so the check runs
# a short campaign and reads `total_edges` - which is the number that actually matters.
export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_USE_ASAN=1 AFL_NO_UI=1
rm -rf {root}/chk
timeout 40 afl-fuzz -i in -o {root}/chk -V 5 -- ./bin/target @@ >{root}/chk.log 2>&1 || true
EDGES=$(grep -E "^total_edges" {root}/chk/default/fuzzer_stats 2>/dev/null | tr -dc "0-9" || echo 0)
echo "MAP_EDGES=$EDGES"
if [ "${{EDGES:-0}}" -lt 200 ]; then
  echo "TARGET_NOT_INSTRUMENTED: only ${{EDGES:-0}} total edges;" \
       "the parser is probably not instrumented" >&2
  exit 3
fi
rm -rf {root}/chk {root}/chk.log
echo BUILD_OK
"""
    result = wsl([script], timeout=600)
    if "TARGET_NOT_INSTRUMENTED" in result.stderr or "TARGET_NOT_INSTRUMENTED" in result.stdout:
        raise RuntimeError(f"instrumentation check failed:\n{result.tail(30)}")
    if not result.ok or "BUILD_OK" not in result.stdout:
        raise RuntimeError(f"build failed:\n{result.tail(30)}")
    return {
        "target": f"{WSL_ROOT}/bin/target",
        "hook": f"{WSL_ROOT}/bin/hook.so",
        "map_edges": next(
            (line.split("=", 1)[1] for line in result.stdout.splitlines() if line.startswith("MAP_EDGES=")),
            "unknown",
        ),
        "cjson_sha256": next(
            (
                line.split("=", 1)[1]
                for line in result.stdout.splitlines()
                if line.startswith("CJSON_SHA256=")
            ),
            "unknown",
        ),
    }


def corpus_fingerprint() -> str:
    """Digest of the seed corpus, so two reports can be checked for using the same inputs."""
    result = wsl([f"cd {WSL_ROOT}/in && cat * | sha256sum | cut -d' ' -f1"], timeout=60, check=True)
    return result.stdout.strip()


def run_campaign(
    arm: Arm,
    seed: int,
    *,
    budget_seconds: int,
    repo_root: Path,
    target_name: str = "cjson",
) -> tuple[RunStats, list[CrashRecord], str]:
    """Run one arm on one seed for a fixed wall-clock budget.

    Returns ``(stats, crashes, mechanism)``. The budget is enforced by AFL++'s own ``-V``:
    stopping it from outside with a signal would leave ``fuzzer_stats`` mid-write and turn a
    budgeted run into a partially recorded one.

    ``-t 1000`` and ``-m none`` are not cosmetic. Without an explicit exec timeout AFL++ derives
    one from the dry run (20 ms here) and a campaign can get stuck re-executing a pathological
    input past its ``-V`` deadline - observed as an ``afl-fuzz`` still running eighteen minutes
    into a two-minute budget. ``-m none`` is required for ASAN, whose shadow memory does not fit
    inside AFL++'s default memory limit. A hard external ``timeout -s KILL`` sits behind both so
    that a hang can never consume the whole experiment.
    """
    root = WSL_ROOT
    out = f"{root}/out/{arm.name}-{seed}"
    decisions = f"{root}/out/{arm.name}-{seed}.decisions.jsonl"

    env_parts = [f"{key}={value}" for key, value in _AFL_ENV.items()]
    if arm.uses_plugin:
        env_parts.append(f"AFL_CUSTOM_MUTATOR_LIBRARY={root}/bin/hook.so")
        env_parts.append(f"FUZZLAB_MODE={arm.mode}")
        env_parts.append(f"FUZZLAB_LOG={decisions}")
        env_parts.extend(f"{key}={value}" for key, value in arm.env.items())

    env_prefix = " ".join(env_parts)
    script = (
        f"cd {root} && mkdir -p {root}/out && rm -rf {out} {decisions} && "
        f"{env_prefix} timeout -s KILL {budget_seconds + 90} "
        f"afl-fuzz -i in -o {out} -V {budget_seconds} -s {seed} -t 1000 -m none "
        f"-- ./bin/target @@ > {out}.log 2>&1; echo EXIT=$?"
    )
    result = wsl([script], timeout=budget_seconds + 180)
    stats_path = f"{root}/out/{arm.name}-{seed}/default/fuzzer_stats"

    probe = wsl([f"test -f {stats_path} && echo YES || echo NO"], timeout=60)
    if "YES" not in probe.stdout:
        raise RuntimeError(
            f"campaign {arm.name}/{seed} produced no fuzzer_stats; afl-fuzz said:\n{result.tail(20)}"
        )

    stats_text = wsl([f"cat {stats_path}"], timeout=60, check=True).stdout
    stats = parse_fuzzer_stats(stats_text, arm=arm.name, seed=seed)

    crashes = _collect_crashes(arm, seed, target_name=target_name)
    mechanism = "stock" if not arm.uses_plugin else str(arm.mode)
    return stats, crashes, mechanism


def _collect_crashes(arm: Arm, seed: int, *, target_name: str) -> list[CrashRecord]:
    """Replay every crash AFL++ saved and give it a signature.

    The signature is computed in the same environment the crash happened in - same binary,
    same sanitizer - because that is what makes it comparable across arms. A crash that
    cannot be replayed is still recorded, with the ``unreproducible`` signature, rather than
    dropped: silently discarding it would inflate the metric it belongs to.
    """
    root = WSL_ROOT
    crash_dir = f"{root}/out/{arm.name}-{seed}/default/crashes"
    listing = wsl(
        [f"ls -1 {crash_dir} 2>/dev/null | grep -v README | head -200 || true"], timeout=60
    ).stdout
    names = [line.strip() for line in listing.splitlines() if line.strip()]
    records: list[CrashRecord] = []
    for name in names:
        replay = wsl(
            [f"cd {root} && ./bin/target '{crash_dir}/{name}' 2>&1 | head -40 || true"],
            timeout=60,
        )
        output = replay.stdout
        if "Sanitizer" not in output and "signal" not in output.lower():
            signature, kind, top_frame = "unreproducible", "unreproducible", ""
        else:
            signature, kind, top_frame = crash_signature(output)
        size_probe = wsl([f"stat -c %s '{crash_dir}/{name}'"], timeout=40).stdout.strip()
        records.append(
            CrashRecord(
                arm=arm.name,
                seed=seed,
                path=Path(f"{crash_dir}/{name}"),
                signature=signature,
                kind=kind,
                top_frame=top_frame,
                input_size=int(size_ok) if (size_ok := size_probe).isdigit() else 0,
            )
        )
    return records


def decision_log_path(arm: Arm, seed: int) -> str:
    """Where the plugin wrote its admission decisions for this campaign."""
    return f"{WSL_ROOT}/out/{arm.name}-{seed}.decisions.jsonl"


def decision_summary(arm: Arm, seed: int) -> dict[str, Any]:
    """Read the plugin's decision log, if the arm used the plugin.

    This is the *mechanism* evidence: a policy that wins but barely changed the admission
    pattern won for some other reason, and a policy that changed it a lot but lost is a
    result worth reporting too.
    """
    path = decision_log_path(arm, seed)
    text = wsl([f"cat {path} 2>/dev/null || true"], timeout=60).stdout
    if not text.strip():
        return {}
    decided = admitted = skipped = 0
    scores: list[float] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if payload.get("event") == "decide":
            decided += 1
            admitted += int(payload.get("admit", 0))
            skipped += 1 - int(payload.get("admit", 0))
            scores.append(float(payload.get("score", 0.0)))
    return {
        "decisions": decided,
        "admitted": admitted,
        "skipped": skipped,
        "admit_ratio": round(admitted / decided, 4) if decided else 0.0,
        "score_mean": round(sum(scores) / len(scores), 4) if scores else 0.0,
    }


def clean() -> None:
    """Remove the WSL work tree. Used before a fresh experiment and after a failure."""
    wsl([f"rm -rf {WSL_ROOT}"], timeout=60)


def have_wsl() -> bool:
    """Whether the fuzzing distribution is reachable at all."""
    if shutil.which("wsl") is None:
        return False
    return wsl(["echo ready"], timeout=60).stdout.strip() == "ready"
