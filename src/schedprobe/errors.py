"""Exception hierarchy for schedprobe.

Design rule: every exception carries a machine-readable ``code`` so the CLI can
map failures onto stable exit codes, and tests can assert on ``code`` instead of
on message text (messages are allowed to change).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "SchedProbeError",
    "ConfigError",
    "TargetValidationError",
    "BudgetError",
    "EvidenceError",
    "BackendError",
    "PolicyError",
]


class SchedProbeError(Exception):
    """Base class for all schedprobe errors."""

    code = "E_GENERIC"
    exit_code = 2

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = dict(context)

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "context": self.context}

    def __str__(self) -> str:  # pragma: no cover - trivial
        if not self.context:
            return self.message
        ctx = ", ".join(f"{k}={v!r}" for k, v in sorted(self.context.items()))
        return f"{self.message} ({ctx})"


class ConfigError(SchedProbeError):
    """Configuration file or CLI option is invalid."""

    code = "E_CONFIG"


class TargetValidationError(SchedProbeError):
    """A target specification was rejected by the safety validator."""

    code = "E_TARGET"


class BudgetError(SchedProbeError):
    """A budget-related value is inconsistent (e.g. reserved > total)."""

    code = "E_BUDGET"


class EvidenceError(SchedProbeError):
    """Evidence log integrity failure (hash chain broken, tampered, truncated)."""

    code = "E_EVIDENCE"


class BackendError(SchedProbeError):
    """A scan backend failed in a way that is not a per-probe outcome."""

    code = "E_BACKEND"


class PolicyError(SchedProbeError):
    """A policy guard refused an operation (e.g. rate limit, unsafe flag combo)."""

    code = "E_POLICY"
