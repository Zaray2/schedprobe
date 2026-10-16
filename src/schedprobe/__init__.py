"""schedprobe - budget-aware, auditable TCP probe scheduler for authorized testing.

The public API is intentionally small and stable::

    from schedprobe import ScanEngine, ScanConfig, load_config, FakeBackend

See ``docs/architecture.md`` for the module map and data flow.
"""

from __future__ import annotations

from .config import ScanConfig, config_from_dict, config_to_dict, default_config, load_config
from .engine import ScanEngine, ScanRun
from .errors import (
    BackendError,
    BudgetError,
    ConfigError,
    EvidenceError,
    PolicyError,
    SchedProbeError,
    TargetValidationError,
)
from .models import PlannedProbe, PortState, ProbeResult, SegmentState, Verdict

__version__ = "0.1.0"

__all__ = [
    "BackendError",
    "BudgetError",
    "ConfigError",
    "EvidenceError",
    "PlannedProbe",
    "PolicyError",
    "PortState",
    "ProbeResult",
    "ScanConfig",
    "ScanEngine",
    "ScanRun",
    "SchedProbeError",
    "SegmentState",
    "TargetValidationError",
    "Verdict",
    "__version__",
    "config_from_dict",
    "config_to_dict",
    "default_config",
    "load_config",
]
