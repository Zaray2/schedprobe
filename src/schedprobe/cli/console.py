"""Shared CLI plumbing: exit codes, printing, and one place where every subcommand returns.

Exit code contract (documented in ``README`` and asserted in the test suite):

===  ==========================================================================
0    success
1    unexpected internal error
2    invalid input, configuration or target scope
3    evidence integrity failure (hash chain broken / manifest mismatch)
4    replay divergence (planner is not deterministic, or the log was edited)
5    capability unavailable in this environment (e.g. missing optional tool)
130  interrupted by the operator
===  ==========================================================================

The single most important property here: **every path returns an exit code and
nothing swallows an exception**. ``run_cli`` is the only place that catches, and it
maps typed errors to codes; anything untyped is reported as an internal error with
a traceback rather than being disguised as success.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback
from collections.abc import Awaitable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from ..errors import (
    BackendError,
    BudgetError,
    ConfigError,
    EvidenceError,
    PolicyError,
    SchedProbeError,
    TargetValidationError,
)

__all__ = [
    "ASCII_FALLBACK_GLYPHS",
    "EXIT_EVIDENCE",
    "EXIT_INTERNAL",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_REPLAY",
    "EXIT_UNAVAILABLE",
    "EXIT_USAGE",
    "Emitter",
    "configure_stdio",
    "env_default",  # embedding API
    "exit_code_for",
    "read_json_file",  # embedding API
    "run_async",
]

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_EVIDENCE = 3
EXIT_REPLAY = 4
EXIT_UNAVAILABLE = 5
EXIT_INTERRUPTED = 130

# Characters the renderer emits that are not ASCII (arguments, labels and ports
# always are). When stdout cannot represent them we substitute these instead of
# letting Python raise UnicodeEncodeError or silently print '?'.
ASCII_FALLBACK_GLYPHS: dict[str, str] = {
    "\u2014": "--",  # em dash
    "\u2013": "-",  # en dash
    "\u00b7": "-",  # middle dot
    "\u2265": ">=",
    "\u2264": "<=",
    "\u2026": "...",
}


def configure_stdio() -> str:
    """Make stdout/stderr able to carry the tool's own output.

    Windows consoles frequently default Python's stdout to a legacy code page
    (``gbk`` on zh-CN systems), which turns any non-ASCII character into ``?`` and
    can raise :class:`UnicodeEncodeError` on an unrepresentable one. We try to
    reconfigure to UTF-8, then degrade gracefully:

    * UTF-8 available  -> output is written verbatim;
    * reconfigure missing/refused -> :func:`schedprobe.reporting.sanitize` will drop
      characters the stream cannot encode, so output is still valid, just folded.

    Returns the encoding that ended up in effect, for logging and tests.
    """
    encoding = "utf-8"
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
                continue
            except (ValueError, OSError, LookupError):  # pragma: no cover - platform dependent
                pass
        encoding = getattr(stream, "encoding", None) or "ascii"
    return encoding


T = TypeVar("T")


@dataclass(slots=True)
class Emitter:
    """Prints to stdout, and to stderr only when a subcommand has something to warn about.

    ``quiet`` silences progress chatter but never silences errors; ``json_mode``
    suppresses human text entirely so stdout stays machine-parseable.
    """

    quiet: bool = False
    json_mode: bool = False
    stream: Any = None

    def __post_init__(self) -> None:
        if self.stream is None:
            self.stream = sys.stdout

    def say(self, *parts: Any, force: bool = False) -> None:
        if self.json_mode and not force:
            return
        if self.quiet and not force:
            return
        print(*parts, file=self.stream)

    def data(self, payload: Mapping[str, Any] | Sequence[Any]) -> None:
        """Emit a machine-readable payload on stdout, in both text and JSON modes.

        The two modes used to have identical branches, which made ``--json`` a no-op:
        the payload was printed either way, just with different variable names.
        """
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), file=self.stream)

    def warn(self, message: str) -> None:
        if self.quiet:
            return
        print(f"warning: {message}", file=sys.stderr)

    def error(self, message: str) -> None:
        print(f"error: {message}", file=sys.stderr)


def run_async(coro: Awaitable[T]) -> T:
    """Run a coroutine with a Ctrl-C contract that does not lose evidence.

    ``asyncio.run`` propagates ``KeyboardInterrupt`` to us; we convert it into
    :class:`_Interrupted` so the caller can map it to exit code 130 while the
    engine's ``finally`` blocks have already flushed and closed the evidence log.
    """

    async def _wrap() -> T:
        return await coro

    try:
        return asyncio.run(_wrap())
    except KeyboardInterrupt as exc:  # pragma: no cover - depends on a real console
        raise RunInterruptedError() from exc


class RunInterruptedError(Exception):
    """Raised when the operator interrupts a run; mapped to exit code 130."""


def exit_code_for(exc: BaseException) -> int:
    if isinstance(exc, RunInterruptedError):
        return EXIT_INTERRUPTED
    if isinstance(exc, EvidenceError):
        return EXIT_EVIDENCE
    if isinstance(exc, (ConfigError, TargetValidationError, BudgetError, PolicyError, BackendError)):
        return EXIT_USAGE
    if isinstance(exc, SchedProbeError):
        return EXIT_USAGE
    return EXIT_INTERNAL


def read_json_file(path: str | os.PathLike[str]) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError("file not found", path=str(path)) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON: {exc}", path=str(path)) from exc


def env_default(name: str, default: str | None = None) -> str | None:
    """Read an environment variable for a *non-secret* default.

    Only paths and presets are read this way. Credentials are deliberately not
    supported anywhere in the tool, so there is nothing secret to read.
    """
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def format_error(exc: BaseException) -> str:
    if isinstance(exc, SchedProbeError):
        return str(exc)
    return f"{exc.__class__.__name__}: {exc}"


def internal_traceback(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def summarise_mapping(payload: Mapping[str, Any], keys: Iterable[str]) -> str:
    return ", ".join(f"{key}={payload.get(key)}" for key in keys if key in payload)
