"""Documentation consistency, tested instead of trusted.

A review of this project made a fair and specific complaint: the exit-code table declared
``EXIT_UNAVAILABLE = 5`` and then a footnote admitted that no code path returns it. That
is a documentation bug with a mechanical cause - nothing connected the prose to the
constants - so it can be prevented mechanically.

Four checks, each of which would have caught a real defect that actually shipped:

* **every exported exit code is reachable** - the ``EXIT_UNAVAILABLE`` class. A documented
  constant with no ``return`` site is a promise the tool cannot keep, and a script that
  branches on it waits forever.
* **every documented relative link resolves** - a review found the README pointing at
  ``tests/test_diff.py``, ``tests/test_adaptive_planner.py`` and ``benchmark-design.md``,
  none of which existed.
* **the front page stays a front page** - the README grew to 466 lines and 38 KB before a
  reader observed that the top of it was an argument about whether the project worked at
  all. The budget below is the fix, and this test is what keeps it.
* **every flag the reference documents exists in the parser** - otherwise the reference
  describes a tool that is not this one.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

from .tiers import TIER_CONSISTENCY, TIER_ORACLE, tier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schedprobe.cli.main import build_parser  # noqa: E402

SRC = ROOT / "src" / "schedprobe"
README = ROOT / "README.md"
CLI_DOC = ROOT / "docs" / "cli.md"

# The front page has to answer "what is this, how do I run it, what does it look like"
# and then get out of the way. Raised only with a reason.
README_LINE_BUDGET = 200


def _python_sources() -> list[Path]:
    return sorted(p for p in ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def _markdown_files() -> list[Path]:
    return sorted(
        list(ROOT.glob("*.md")) + list(ROOT.glob("docs/**/*.md")) + list(ROOT.glob("examples/**/*.md"))
    )


@tier(TIER_CONSISTENCY)
class TestExitCodesAreReachable(unittest.TestCase):
    """The defect a reviewer found: a constant documented but never returned."""

    def test_every_exported_exit_code_has_a_return_site(self) -> None:
        console = (SRC / "cli" / "console.py").read_text(encoding="utf-8")
        declared = set(re.findall(r"^(EXIT_[A-Z_]+) = \d+", console, re.M))
        self.assertTrue(declared, "no exit codes found - did the declaration style change?")

        offenders: list[str] = []
        for name in sorted(declared):
            used = False
            for path in _python_sources():
                text = path.read_text(encoding="utf-8")
                # A *return site*, not merely a reference: the declaration itself is a
                # reference too, and so is an entry in ``__all__``, and neither of those
                # means a caller can ever receive the code. ``console.py`` is included
                # because ``exit_code_for`` and ``run_async`` live there.
                if re.search(rf"\breturn {name}\b", text):
                    used = True
                    break
            if not used:
                offenders.append(name)
        self.assertEqual(
            offenders,
            [],
            "these exit codes are exported and documented but no code path returns them; "
            "either wire them to a real condition or stop advertising them: " + ", ".join(offenders),
        )

    def test_the_documented_table_matches_the_constants(self) -> None:
        console = (SRC / "cli" / "console.py").read_text(encoding="utf-8")
        declared = {int(value) for value in re.findall(r"^EXIT_[A-Z_]+ = (\d+)", console, re.M)}
        documented = {
            int(value)
            for value in re.findall(r"^\|\s*`(\d{1,3})`\s*\|", CLI_DOC.read_text(encoding="utf-8"), re.M)
        }
        self.assertEqual(
            documented,
            declared,
            f"exit codes documented but not declared: {sorted(documented - declared)}; "
            f"declared but not documented: {sorted(declared - documented)}",
        )


@tier(TIER_ORACLE)
class TestLinksResolve(unittest.TestCase):
    def test_every_relative_markdown_link_points_at_a_real_file(self) -> None:
        broken: list[str] = []
        for md in _markdown_files():
            text = md.read_text(encoding="utf-8")
            for match in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", text):
                target = match.group(1).strip()
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                target = target.split("#", 1)[0]
                if not target:
                    continue
                if not (md.parent / target).resolve().exists():
                    broken.append(f"{md.relative_to(ROOT)} -> {target}")
        self.assertEqual(broken, [], "broken relative links:\n  " + "\n  ".join(broken))


@tier(TIER_CONSISTENCY)
class TestReadmeStaysAFrontPage(unittest.TestCase):
    def test_line_budget(self) -> None:
        lines = README.read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(
            len(lines),
            README_LINE_BUDGET,
            f"README is {len(lines)} lines, over the {README_LINE_BUDGET}-line budget. "
            "The front page answers 'what is this / how do I run it / what does it look "
            "like' and links out; long-form material belongs in docs/.",
        )

    def test_opens_with_what_it_is_not_a_status_caveat(self) -> None:
        # A reviewer's summary of the old front page was "a beautifully wrapped box with a
        # note saying the box is unverified". The first screen has to say what the tool is.
        head = "\n".join(README.read_text(encoding="utf-8").splitlines()[:30])
        self.assertNotIn("未验证", head)
        self.assertNotIn("not verified", head.lower())
        self.assertIn("schedprobe", head)

    def test_links_to_the_reference_instead_of_inlining_it(self) -> None:
        text = README.read_text(encoding="utf-8")
        self.assertIn("docs/cli.md", text)
        # The full option table lives in docs/cli.md; the front page should not carry a
        # second copy that can drift out of sync with it.
        table_rows = len(re.findall(r"^\|\s*`--[a-z-]+`", text, re.M))
        self.assertLessEqual(
            table_rows, 12, f"README carries {table_rows} option rows; keep them in docs/cli.md"
        )


@tier(TIER_CONSISTENCY)
class TestCliReferenceMatchesTheParser(unittest.TestCase):
    def test_documented_flags_exist(self) -> None:
        parser = build_parser()
        known: set[str] = set()
        for action in parser._actions:
            known.update(action.option_strings)
            for sub in (
                getattr(action, "choices", {}).values()
                if isinstance(getattr(action, "choices", None), dict)
                else []
            ):
                for sub_action in sub._actions:
                    known.update(sub_action.option_strings)

        documented = set(re.findall(r"`(--[a-z][a-z-]+)", CLI_DOC.read_text(encoding="utf-8")))
        self.assertTrue(documented, "no flags documented - did the doc format change?")
        missing = sorted(flag for flag in documented if flag not in known)
        self.assertEqual(missing, [], f"docs/cli.md documents flags the parser does not define: {missing}")

    def test_every_subcommand_is_documented(self) -> None:
        parser = build_parser()
        subparsers = [
            action for action in parser._actions if action.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subparsers), 1, "expected exactly one subparser group")
        commands = set(subparsers[0].choices)
        doc = CLI_DOC.read_text(encoding="utf-8")
        undocumented = sorted(name for name in commands if f"## `{name}`" not in doc)
        self.assertEqual(undocumented, [], f"subcommands missing from docs/cli.md: {undocumented}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
