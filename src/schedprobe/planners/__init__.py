"""Planner implementations. ``build_planner`` maps a config to a concrete class."""

from __future__ import annotations

from typing import Sequence

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

__all__ = [
    "AdaptivePlanner",
    "FixedLongTimeoutPlanner",
    "FixedOrderPlanner",
    "RandomOrderPlanner",
    "Planner",
    "SegmentBook",
    "RttTracker",
    "ProbePlan",
    "RankUpdate",
    "LiveSetChange",
    "pair_key",
    "PLANNER_CLASSES",
    "build_planner",
]

PLANNER_CLASSES: dict[str, type[Planner]] = {
    AdaptivePlanner.name: AdaptivePlanner,
    FixedOrderPlanner.name: FixedOrderPlanner,
    RandomOrderPlanner.name: RandomOrderPlanner,
    FixedLongTimeoutPlanner.name: FixedLongTimeoutPlanner,
}


def build_planner(kind: str, hosts: Sequence[str], ports: Sequence[int], config) -> Planner:
    """Instantiate a planner by name from a validated config."""
    try:
        cls = PLANNER_CLASSES[kind]
    except KeyError as exc:
        raise ConfigError(
            "unknown planner", kind=kind, known=sorted(PLANNER_CLASSES)
        ) from exc
    return cls(hosts, ports, config)
