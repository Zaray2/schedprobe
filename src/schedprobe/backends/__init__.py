"""Compatibility shim so both ``schedprobe.backends`` and ``schedprobe.backends.<x>`` import cleanly."""

from __future__ import annotations

from .base import (  # noqa: F401
    Backend,
    BackendStats,
    ProbeRequest,
    RateLimiter,
    ScopedProbeBackend,
    build_backend,
    confidence_for,
    merge_stats,
)

__all__ = [
    "Backend",
    "BackendStats",
    "ProbeRequest",
    "RateLimiter",
    "ScopedProbeBackend",
    "build_backend",
    "confidence_for",
    "merge_stats",
]
