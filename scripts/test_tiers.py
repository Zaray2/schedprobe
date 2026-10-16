"""Print the evidence-tier distribution of the test suite.

Exists so that the answer to "how much of this suite can actually falsify a belief?" is a
command anyone can run rather than a sentence in a README. A reviewer asked exactly that
question, and the honest reply is a number with a method behind it.

    python scripts/test_tiers.py
    python scripts/test_tiers.py --list      # every test, with its tier
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.test_tier_coverage import collect  # noqa: E402
from tests.tiers import TIER_MEANING  # noqa: E402

ORDER = ("oracle", "contract", "consistency")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="list every test with its tier")
    args = parser.parse_args()

    rows = collect()
    by_tier: dict[str, list[str]] = defaultdict(list)
    by_module: dict[str, dict[str, int]] = defaultdict(lambda: dict.fromkeys(ORDER, 0))
    for module, klass, method, tier in rows:
        key = tier or "(undeclared)"
        by_tier[key].append(f"{module}.{klass}.{method}")
        if tier in by_module[module]:
            by_module[module][tier] += 1

    total = len(rows)
    print(f"tests collected: {total}")
    print()
    print("by tier — the tier is what would have to change for the test to fail")
    print("-" * 78)
    for name in ORDER:
        count = len(by_tier.get(name, []))
        share = count / total if total else 0.0
        bar = "#" * round(share * 48)
        print(f"  {name:<12} {count:>4}  {share:>6.1%}  {bar}")
        print(f"  {'':<12} {TIER_MEANING[name]}")
    undeclared = len(by_tier.get("(undeclared)", []))
    if undeclared:
        print(f"  {'UNDECLARED':<12} {undeclared:>4}   <- the coverage test rejects this")
    print()
    print("by module")
    print("-" * 78)
    print(f"  {'module':<32} {'oracle':>7} {'contract':>9} {'consistency':>12} {'total':>7}")
    for module in sorted(by_module):
        counts = by_module[module]
        row_total = sum(counts.values())
        print(
            f"  {module:<32} {counts['oracle']:>7} {counts['contract']:>9} "
            f"{counts['consistency']:>12} {row_total:>7}"
        )

    if args.list:
        print()
        for name in ORDER:
            print(f"=== {name} ===")
            for item in sorted(by_tier.get(name, [])):
                print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
