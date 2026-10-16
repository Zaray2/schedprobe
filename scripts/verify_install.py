"""Offline installation check.

`pip install -e .` needs a build backend (setuptools) and, on a machine without a
package index, that download fails for reasons that have nothing to do with this
project. This script proves the *packaging* claim without a network:

1. copy ``src/schedprobe`` to a temporary directory that stands in for ``site-packages``;
2. validate ``pyproject.toml`` parses and every file it references exists;
3. run the CLI with only that directory on ``sys.path``, from an unrelated working
   directory, so an accidental dependency on the repository root shows up as a failure;
4. exercise the documented entry points (``version``, ``demo``, ``verify``, ``replay``)
   against a run produced in a scratch directory.

Exit code 0 means "the shipped package works when installed"; a non-zero exit prints the
failing step. What it does **not** cover is setuptools' own metadata handling, which is
why the README marks the real ``pip install`` as unverified in this environment rather
than claiming it was tested.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(step: str, detail: str) -> int:
    print(f"FAIL [{step}] {detail}")
    return 1


def main() -> int:
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.is_file():
        return fail("metadata", "pyproject.toml is missing")
    with pyproject.open("rb") as handle:
        meta = tomllib.load(handle)
    project = meta.get("project", {})
    print(f"package : {project.get('name')} {project.get('version')}")
    print(f"requires: python {project.get('requires-python')}")
    print(f"runtime dependencies: {project.get('dependencies')}")

    for declared in (project.get("readme"), "LICENSE"):
        if declared and not (ROOT / declared).is_file():
            return fail("metadata", f"declared file {declared!r} does not exist")
    scripts = project.get("scripts", {})
    if "schedprobe" not in scripts:
        return fail("metadata", "no console script declared")
    print(f"entry point: {scripts['schedprobe']}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        site_packages = tmp_path / "site-packages"
        site_packages.mkdir()
        shutil.copytree(ROOT / "src" / "schedprobe", site_packages / "schedprobe")
        # Remove caches so the copy cannot accidentally satisfy an import from the source
        # tree, and run from a directory with nothing in it.
        for cache in site_packages.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
        workdir = tmp_path / "cwd"
        workdir.mkdir()
        out_dir = tmp_path / "runs"

        env = dict(os.environ)
        env["PYTHONPATH"] = str(site_packages)
        env.pop("PYTHONIOENCODING", None)

        def run(args: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-m", "schedprobe", *args],
                cwd=str(workdir),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        result = run(["version"])
        if result.returncode != 0:
            return fail("version", result.stderr.strip()[-300:])
        payload = json.loads(result.stdout)
        if payload["runtime_dependencies"]:
            return fail("version", f"unexpected runtime dependencies: {payload['runtime_dependencies']}")
        print(f"step 1/4  version                OK  ({payload['version']}, {payload['platform']})")

        result = run(
            ["demo", "--scenario", "blackhole-segment", "--budget", "20000", "--out-dir", str(out_dir)]
        )
        if result.returncode != 0:
            return fail("demo", result.stderr.strip()[-300:])
        if "OK   replay" not in result.stdout or "OK   evidence chain" not in result.stdout:
            return fail("demo", "demo did not report a verifiable chain and a matching replay")
        print("step 2/4  demo + Replay/Verify   OK")

        run_dirs = [path for path in out_dir.iterdir() if path.is_dir()]
        if len(run_dirs) != 1:
            return fail("artifact", f"expected exactly one run directory, found {len(run_dirs)}")
        run_dir = run_dirs[0]

        result = run(["verify", str(run_dir)])
        if result.returncode != 0:
            return fail("verify", result.stdout.strip()[-200:] + result.stderr.strip()[-200:])
        print("step 3/4  verify (external call)  OK")

        result = run(["replay", str(run_dir / "evidence.jsonl"), "--strict"])
        if result.returncode != 0:
            return fail("replay --strict", result.stdout.strip()[-300:])
        print("step 4/4  replay --strict         OK")

        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        print(f"          evidence records       : {manifest['evidence_records']}")
        print(f"          chain head             : {manifest['chain_head'][:24]}...")
        print(f"          probe errors           : {manifest['probe_errors']}")

    print("\nOK: the package works when placed on sys.path as an installed package.")
    print("NOTE: `pip install -e .` itself needs a build backend (setuptools) from a package")
    print("      index; that download is unavailable in this environment, so the editable")
    print("      install is reported as unverified rather than as passing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
