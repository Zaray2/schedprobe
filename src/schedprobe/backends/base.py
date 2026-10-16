"""Backend protocol, confidence scoring, and shared probe result construction.

A *backend* is anything that can answer "what is the state of this (host, port)?"
The simulation backend and the real TCP backend implement the same tiny protocol,
which is what lets the benchmark, the demo command and the unit tests exercise the
exact same scheduler code path.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, Set

from ..errors import BackendError
from ..models import PortState, ProbeResult, Verdict

__all__ = [
    "ProbeRequest",
    "Backend",
    "BackendStats",
    "ScopedProbeBackend",
    "confidence_for",
    "build_backend",
]

# Base confidence per verdict. Rationale, in one line each:
#   connected    - a completed TCP handshake is about as certain as it gets
#   refused      - an RST says the host is up and the port is closed
#   reset        - an RST after connect: closed, but some middleboxes fake this
#   timeout      - absence of evidence; could be a drop, a slow path, or a loss
#   unreachable  - the host itself did not answer; says nothing about the port
#   error        - we do not know what happened
_BASE_CONFIDENCE: dict[Verdict, float] = {
    Verdict.CONNECTED: 0.99,
    Verdict.REFUSED: 0.95,
    Verdict.RESET: 0.75,
    Verdict.TIMEOUT: 0.45,
    Verdict.CONFIRMED_TIMEOUT: 0.85,
    Verdict.HOST_UNREACHABLE: 0.35,
    Verdict.ERROR: 0.30,
    Verdict.UNRESOLVED: 0.20,
    Verdict.NOT_PROBED: 0.0,
}


def confidence_for(verdict: Verdict, attempt: int = 1) -> float:
    """Confidence in a verdict, boosted (boundedly) by repeated agreement.

    Two independent timeouts are stronger evidence of filtering than one, but the
    boost saturates quickly: ``base + (1-base) * min(1, (attempt-1) * 0.5)``.
    This keeps a retry loop from manufacturing certainty.
    """
    base = _BASE_CONFIDENCE.get(verdict, 0.3)
    if attempt <= 1:
        return round(base, 4)
    boost = min(1.0, (attempt - 1) * 0.5) * (1.0 - base)
    return round(min(1.0, base + boost), 4)


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """One probe to execute. Immutable; the engine constructs these from planner output."""

    host: str
    port: int
    timeout_s: float
    attempt: int = 1
    reason: str = "sweep"
    run_label: str = ""
    # Hard ceiling applied by whichever component serves the probe. The real
    # backend feeds this to asyncio; the simulation backend bills a filtered
    # result at ``min(timeout_s, max_timeout_s)`` so simulated cost tracks what a
    # real probe would have spent. Keeping it on the request (instead of letting
    # each backend guess) is what makes cost numbers comparable across backends.
    max_timeout_s: float = 3.0

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            raise ValueError(f"timeout_s must be > 0, got {self.timeout_s}")
        if self.max_timeout_s <= 0:
            raise ValueError(f"max_timeout_s must be > 0, got {self.max_timeout_s}")
        if self.attempt < 1:
            raise ValueError(f"attempt must be >= 1, got {self.attempt}")

    @property
    def effective_timeout_s(self) -> float:
        return min(self.timeout_s, self.max_timeout_s)


@dataclass(slots=True)
class BackendStats:
    """Counters a backend reports for the run manifest."""

    probes: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    undetermined_count: int = 0
    cost_units: int = 0
    elapsed_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "probes": self.probes,
            "open": self.open_count,
            "closed": self.closed_count,
            "filtered": self.filtered_count,
            "undetermined": self.undetermined_count,
            "cost_units": self.cost_units,
            "elapsed_s": round(self.elapsed_s, 4),
        }


class Backend(Protocol):
    """Structural type for scan backends.

    Implementations must be safe to call concurrently from several tasks and must
    never raise for an ordinary per-probe outcome (timeout, refusal, DNS failure);
    only genuine infrastructure failures should raise :class:`BackendError`.
    """

    name: str
    cost_unit: str

    async def setup(self) -> None:  # pragma: no cover - trivial
        ...

    async def probe(self, request: ProbeRequest) -> ProbeResult:  # pragma: no cover - protocol
        ...

    async def teardown(self) -> None:  # pragma: no cover - trivial
        ...

    def stats(self) -> BackendStats:  # pragma: no cover - protocol
        ...


class ScopedProbeBackend:
    """Mixin that enforces an allow-list of hosts before any probe leaves the box.

    Both shipped backends inherit this. The check is deliberately in the backend
    layer as well as in ``targets.validate_targets``: config validation could be
    bypassed by a library caller constructing a backend directly, and defence in
    depth here costs one set lookup.
    """

    name = "scoped"
    cost_unit = "unit"

    def __init__(self, allow: Set[str] | None = None) -> None:
        self._allowed: Set[str] | None = set(allow) if allow is not None else None
        self._stats = BackendStats()
        self._started = 0.0

    def _assert_scoped(self, host: str) -> None:
        if self._allowed is not None and host not in self._allowed:
            raise BackendError(
                "probe target is outside the validated scope", host=host,
                hint="build the backend from a validated ScanConfig",
            )

    async def setup(self) -> None:
        self._started = time.monotonic()

    async def teardown(self) -> None:
        if self._started:
            self._stats.elapsed_s = time.monotonic() - self._started

    def stats(self) -> BackendStats:
        return self._stats


def build_backend(kind: str, config, hosts: list[str], **kwargs: Any) -> Backend:
    """Instantiate a backend by name, injecting the validated host allow-list.

    ``kwargs`` is the union of everything any backend might want (``scenario`` for the
    simulator, ``grab_banner`` for the real one). Each branch takes what it needs and
    drops the rest; passing the union straight through was a real bug - the real
    backend used to raise ``TypeError: unexpected keyword argument 'scenario'`` on
    every ``--backend real`` run.
    """
    from .fake import FakeBackend  # local import: keeps module import cheap

    if kind == "fake":
        return FakeBackend(scenario=kwargs.get("scenario"), allow=hosts, config=config)
    if kind == "real":
        from .real import RealTcpBackend

        return RealTcpBackend(
            config=config,
            allow=hosts,
            grab_banner=bool(kwargs.get("grab_banner", False)),
            rate_limit_pps=kwargs.get("rate_limit_pps"),
        )
    raise BackendError("unknown backend", kind=kind, known=["fake", "real"])


def merge_stats(target: BackendStats, result: ProbeResult) -> None:
    """Fold one probe result into a stats object (shared by backends)."""
    target.probes += 1
    target.cost_units += result.cost_units
    if result.state is PortState.OPEN:
        target.open_count += 1
    elif result.state is PortState.CLOSED:
        target.closed_count += 1
    elif result.state is PortState.FILTERED:
        target.filtered_count += 1
    else:
        target.undetermined_count += 1


def sleep_for(seconds: float) -> Any:
    """Indirection so tests can patch out real waiting."""
    return asyncio.sleep(max(0.0, seconds))


@dataclass(slots=True)
class RateLimiter:
    """Simple token bucket shared by concurrent probes.

    ``rate`` is probes-per-second; ``0`` disables limiting. The limiter is
    deliberately coarse (one token per probe, no burst parameter) because the
    goal is 'do not hammer the target', not traffic shaping.
    """

    rate: float = 0.0
    _next_slot: float = field(default=0.0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    async def acquire(self) -> float:
        if self.rate <= 0:
            return 0.0
        interval = 1.0 / self.rate
        async with self._lock:
            now = time.monotonic()
            if self._next_slot < now:
                self._next_slot = now
            wait = self._next_slot - now
            self._next_slot += interval
        if wait > 0:
            await sleep_for(wait)
        return wait
