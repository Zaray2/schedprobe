"""Map exactly which artifact leaks which sensitive string.

Answers the P0 question "does --redact cover every output path?" with evidence rather
than intent: run a scan with a recognisable target, label and note, then grep every file
that was written.

    python scripts/audit_redaction.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "runs-audit"

TARGET = "10.77.88.9"
LABEL = "LABEL-CANARY-6f2a"
NOTES = "NOTES-CANARY-9c41 confidential engagement reference"
AUTH = "AUTH-CANARY-4d17"


def scan(*extra: str) -> Path:
    shutil.rmtree(OUT, ignore_errors=True)
    cmd = [
        sys.executable,
        "-m",
        "schedprobe",
        "scan",
        "-t",
        TARGET,
        "-p",
        "80,443",
        "--backend",
        "fake",
        "--scenario",
        "healthy",
        "--budget",
        "5000",
        "--out-dir",
        str(OUT),
        "--label",
        LABEL,
        "--notes",
        NOTES,
        "--authorization",
        AUTH,
        *extra,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f"scan failed (exit {proc.returncode}): {proc.stderr[-400:]}")
        raise SystemExit(1)
    runs = [p for p in OUT.iterdir() if p.is_dir()]
    if len(runs) != 1:
        print(f"expected 1 run dir, found {len(runs)}")
        raise SystemExit(1)
    return runs[0]


def probe(run: Path, needles: dict[str, str]) -> dict[str, dict[str, int]]:
    """Return {filename: {needle_label: hit_count}} for every file in the run."""
    result: dict[str, dict[str, int]] = {}
    for path in sorted(run.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        counts = {name: text.count(value) for name, value in needles.items()}
        if any(counts.values()):
            result[str(path.relative_to(run))] = counts
    return result


def main() -> int:
    needles = {"target": TARGET, "label": LABEL, "notes": NOTES, "auth": AUTH}

    print("=" * 78)
    print("RUN A: --redact")
    print("=" * 78)
    run = scan("--redact", "--format", "json")
    produced = sorted(p.name for p in run.iterdir())
    print(f"run dir: {run.name}")
    for name in produced:
        print(f"  produced: {name}")
    leaked_a = probe(run, needles)

    print("\n-- files that still contain a canary --")
    if not leaked_a:
        print("  (none)")
    for filename, counts in leaked_a.items():
        present = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
        print(f"  {filename:<34} {present}")

    print()
    print("=" * 78)
    print("RUN B: no --redact (control: everything should leak)")
    print("=" * 78)
    run_b = scan("--format", "json")
    leaked_b = probe(run_b, needles)
    print("-- files that contain a canary --")
    for filename, counts in leaked_b.items():
        present = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
        print(f"  {filename:<34} {present}")

    print()
    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"artifacts written                : {produced}")
    print(f"files leaking with --redact      : {len(leaked_a)}")
    print(f"files leaking without --redact   : {len(leaked_b)}")
    redacted_only = set(leaked_b) - set(leaked_a)
    print(f"files --redact actually covers   : {sorted(redacted_only) or '(none)'}")
    still_leaking = sorted(set(leaked_a))
    print(f"files --redact does NOT cover    : {still_leaking}")

    shutil.rmtree(OUT, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
