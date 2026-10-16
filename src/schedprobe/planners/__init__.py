"""Planner implementations. ``build_planner`` maps a config to a concrete class."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..errors import ConfigError
from .adaptive import (
    AdaptivePlanner,
    FixedLongTimeoutPlanner,
    FixedOrderPlanner,
    RandomOrderPlanner,
)
from .base import (
    LiveSetChange,
    Planner,
    ProbePlan,
    RankUpdate,
    RttTracker,
    SegmentBook,
    pair_key,
)

if TYPE_CHECKING:
    from ..config import PlannerConfig

__all__ = [
    "PLANNER_CLASSES",
    "AdaptivePlanner",
    "FixedLongTimeoutPlanner",
    "FixedOrderPlanner",
    "LiveSetChange",
    "Planner",
    "ProbePlan",
    "RandomOrderPlanner",
    "RankUpdate",
    "RttTracker",
    "SegmentBook",
    "build_planner",
    "pair_key",
]

PLANNER_CLASSES: dict[str, type[Planner]] = {
    AdaptivePlanner.name: AdaptivePlanner,
    FixedOrderPlanner.name: FixedOrderPlanner,
    RandomOrderPlanner.name: RandomOrderPlanner,
    FixedLongTimeoutPlanner.name: FixedLongTimeoutPlanner,
}


def build_planner(kind: str, hosts: Sequence[str], ports: Sequence[int], config: PlannerConfig) -> Planner:
    """Instantiate a planner by name from a validated config."""
    try:
        cls = PLANNER_CLASSES[kind]
    except KeyError as exc:
        raise ConfigError("unknown planner", kind=kind, known=sorted(PLANNER_CLASSES)) from exc
    return cls(hosts, ports, config)
