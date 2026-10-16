"""schedprobe - budget-aware, auditable TCP probe scheduler for authorized testing.

The public API is intentionally small and stable::

    from schedprobe import ScanEngine, ScanConfig, load_config, FakeBackend

See ``docs/architecture.md`` for the module map and data flow.
"""

from __future__ import annotations

from .config import ScanConfig, load_config, default_config, config_from_dict, config_to_dict
from .engine import ScanEngine, ScanRun
from .models import PortState, ProbeResult, PlannedProbe, SegmentState, Verdict
from .errors import (
    SchedProbeError,
    ConfigError,
    TargetValidationError,
    BudgetError,
    EvidenceError,
    BackendError,
    PolicyError,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ScanConfig",
    "load_config",
    "default_config",
    "config_from_dict",
    "config_to_dict",
    "ScanEngine",
    "ScanRun",
    "PortState",
    "ProbeResult",
    "PlannedProbe",
    "SegmentState",
    "Verdict",
    "SchedProbeError",
    "ConfigError",
    "TargetValidationError",
    "BudgetError",
    "EvidenceError",
    "BackendError",
    "PolicyError",
]
