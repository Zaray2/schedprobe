"""Deterministic simulation backend.

Purpose: give the scheduler a world it can be *measured* in.

The real network cannot be replayed, so any benchmark built on it can only ever
produce anecdotes. This backend replaces it with an explicit, seeded cost model:

* every (host, port) pair has a ground-truth state drawn from a declarative
  scenario;
* a probe costs a deterministic number of *cost units* derived from that state:
  an open port costs its round-trip latency, a refused port costs the same,
  a dropped packet costs the full (capped) timeout - exactly the asymmetry that
  the adaptive planner is designed to exploit;
* per-pair jitter is derived from ``sha256(seed|host|port)`` rather than a global
  RNG, so results do not depend on probe order. Two runs that observe the same
  pairs in different orders see the same costs.

Everything is integer-exact and reproducible: see ``tests/test_engine.py`` (``TestBackendDeterminism``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import BackendError
from ..models import PortState, ProbeResult, Verdict
from ..util import derive_rng
from .base import ProbeRequest, ScopedProbeBackend, confidence_for, merge_stats

__all__ = ["FakeBackend", "NetworkScenario", "builtin_scenarios", "load_scenario", "scenario_from_dict"]


@dataclass(slots=True)
class NetworkScenario:
    """Declarative description of a synthetic network.

    ``hosts`` maps a host literal to its per-port ground truth. ``default`` is the
    state used for ports that are not listed, which is how a /24 full of filtered
    hosts is expressed in three lines instead of 65k.
    """

    name: str
    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    loss_rate: float = 0.0
    latency_ms: tuple[int, int] = (1, 6)
    description: str = ""

    def resolve(self, host: str, port: int) -> PortState:
        entry = self.hosts.get(host)
        if entry is None:
            return PortState.UNDETERMINED
        if entry.get("unreachable"):
            return PortState.FILTERED
        ports = entry.get("ports", {})
        key = str(port)
        if key in ports:
            return PortState(str(ports[key]))
        default = entry.get("default")
        if default is None:
            return PortState.CLOSED
        return PortState(str(default))

    def is_unreachable(self, host: str) -> bool:
        entry = self.hosts.get(host)
        return bool(entry and entry.get("unreachable"))

    def ground_truth(self, hosts: Iterable[str], ports: Sequence[int]) -> dict[tuple[str, int], PortState]:
        truth: dict[tuple[str, int], PortState] = {}
        for host in hosts:
            for port in ports:
                truth[(host, port)] = self.resolve(host, port)
        return truth


def scenario_from_dict(payload: Mapping[str, Any]) -> NetworkScenario:
    if not isinstance(payload, Mapping):
        raise BackendError("scenario must be a mapping")
    hosts_raw = payload.get("hosts", {})
    if not isinstance(hosts_raw, Mapping):
        raise BackendError("scenario.hosts must be a mapping of host -> rules")
    hosts: dict[str, dict[str, Any]] = {}
    for host, rules in hosts_raw.items():
        if not isinstance(rules, Mapping):
            raise BackendError("scenario host rules must be a mapping", host=str(host))
        cleaned: dict[str, Any] = {}
        if "unreachable" in rules:
            cleaned["unreachable"] = bool(rules["unreachable"])
        if "default" in rules:
            cleaned["default"] = PortState(str(rules["default"])).value
        if "ports" in rules:
            ports_raw = rules["ports"]
            if not isinstance(ports_raw, Mapping):
                raise BackendError("scenario host 'ports' must be a mapping", host=str(host))
            cleaned["ports"] = {str(int(k)): PortState(str(v)).value for k, v in ports_raw.items()}
        hosts[str(host)] = cleaned
    latency = payload.get("latency_ms", [1, 6])
    if not (isinstance(latency, Sequence) and len(latency) == 2):
        raise BackendError("scenario.latency_ms must be [low, high]")
    low, high = int(latency[0]), int(latency[1])
    if low < 0 or high < low:
        raise BackendError("scenario.latency_ms must satisfy 0 <= low <= high")
    loss = float(payload.get("loss_rate", 0.0))
    if not 0.0 <= loss <= 1.0:
        raise BackendError("scenario.loss_rate must be within [0, 1]")
    return NetworkScenario(
        name=str(payload.get("name", "custom")),
        hosts=hosts,
        loss_rate=loss,
        latency_ms=(low, high),
        description=str(payload.get("description", "")),
    )


def load_scenario(path: str | Path) -> NetworkScenario:
    file_path = Path(path)
    if not file_path.is_file():
        raise BackendError("scenario file not found", path=str(file_path))
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BackendError(f"scenario is not valid JSON: {exc}", path=str(file_path)) from exc
    return scenario_from_dict(payload)


def builtin_scenarios() -> dict[str, NetworkScenario]:
    """Scenarios used by tests, the demo command and the benchmark harness.

    Written as data so a reader can see the exact world the numbers came from.
    """

    def host(open_ports: Iterable[int], default: PortState, **extra: Any) -> dict[str, Any]:
        rules: dict[str, Any] = {
            "ports": {str(p): PortState.OPEN.value for p in open_ports},
            "default": default.value,
        }
        rules.update(extra)
        return rules

    healthy = {
        "10.0.10.5": host([22, 80, 443], PortState.CLOSED),
        "10.0.10.6": host([22, 3306], PortState.CLOSED),
        "10.0.10.7": host([8080, 8443], PortState.CLOSED),
    }
    # A segment that has nothing listening: an /24 full of dropped packets is the
    # pathological case the adaptive planner is built for.
    blackhole = {f"10.0.20.{i}": {"unreachable": True} for i in range(2, 14)}
    # A large segment that is *heavily filtered* but not dead. No policy can find
    # the open ports cheaply, but a good one should stop paying for the drop after
    # a few attempts and spend the rest of the budget elsewhere.
    segmented_filtered = {
        f"10.0.40.{i}": host([22, 443] if i == 5 else [], PortState.FILTERED) for i in range(2, 14)
    }
    mixed = dict(healthy)
    mixed.update(blackhole)
    mixed.update(
        {
            "10.0.30.5": host([6379, 8080], PortState.CLOSED),
            "10.0.30.6": host([22], PortState.CLOSED),
        }
    )
    return {
        "healthy": NetworkScenario(
            name="healthy",
            hosts=dict(healthy),
            latency_ms=(1, 4),
            description="three responsive hosts, no filtering",
        ),
        "blackhole-segment": NetworkScenario(
            name="blackhole-segment",
            hosts=dict(mixed),
            latency_ms=(1, 6),
            description="one healthy /24, one fully filtered /24, one small mixed /24",
        ),
        "segmented-filtered": NetworkScenario(
            name="segmented-filtered",
            hosts=dict(mixed) | dict(segmented_filtered),
            latency_ms=(1, 6),
            description=("adds a twelve-host /24 that is mostly filtered with two open ports on one host"),
        ),
        "segmented-sweep": NetworkScenario(
            name="segmented-sweep",
            hosts=(
                {
                    f"10.0.60.{i}": ({"unreachable": True} if i <= 10 else host([], PortState.CLOSED))
                    for i in range(2, 14)
                }
                | {
                    "10.0.70.5": host([22, 80, 443], PortState.CLOSED),
                    "10.0.70.6": host([22, 3306, 8080], PortState.CLOSED),
                    "10.0.70.7": host([443, 8443, 6379], PortState.CLOSED),
                    "10.0.80.5": host([22, 6379, 8080], PortState.CLOSED),
                    "10.0.80.6": host([80, 443, 8443], PortState.CLOSED),
                }
            ),
            latency_ms=(1, 5),
            description=(
                "sixty-four ports per host; the first /24 is mostly a black hole, "
                "the two later /24s carry the open ports - the scenario where "
                "giving up early is the difference between finding them and not"
            ),
        ),
        "mixed-lossy": NetworkScenario(
            name="mixed-lossy",
            hosts={
                "10.0.40.5": host([22, 443], PortState.FILTERED),
                "10.0.40.6": host([80], PortState.CLOSED),
                "10.0.40.7": {"unreachable": True},
            },
            loss_rate=0.08,
            latency_ms=(2, 25),
            description="flaky link: 8% packet loss plus partial filtering",
        ),
        "wide-sweep": NetworkScenario(
            name="wide-sweep",
            hosts={
                "10.0.50.5": host([22, 80, 443], PortState.FILTERED),
                "10.0.50.6": host([3306], PortState.FILTERED),
                "10.0.50.7": host([8080], PortState.FILTERED),
            },
            latency_ms=(1, 3),
            description="1024 ports x 3 hosts, overwhelmingly filtered",
        ),
    }


class FakeBackend(ScopedProbeBackend):
    """Serves probes from a :class:`NetworkScenario` with deterministic costs.

    ``cost_unit`` is a simulated microsecond-scale unit; the planner treats it as
    an abstract budget currency. No sleeping happens here - simulated time and
    wall time are deliberately decoupled so a 4000-unit budget runs instantly.
    """

    name = "fake"
    cost_unit = "sim-unit"

    def __init__(
        self,
        scenario: NetworkScenario | str | None = None,
        *,
        allow: Iterable[str] | None = None,
        config: Any = None,
    ) -> None:
        super().__init__(allow=set(allow) if allow is not None else None)
        if isinstance(scenario, str) or scenario is None:
            catalog = builtin_scenarios()
            key = scenario or "blackhole-segment"
            if key not in catalog:
                raise BackendError("unknown built-in scenario", name=key, known=sorted(catalog))
            self.scenario = catalog[key]
        else:
            self.scenario = scenario
        self.config = config
        self.seed = getattr(getattr(config, "planner", None), "seed", 0) if config else 0
        self._loss_seed = f"schedprobe-loss:{self.seed}:{self.scenario.name}"

    # ------------------------------------------------------------------ probing
    async def probe(self, request: ProbeRequest) -> ProbeResult:
        self._assert_scoped(request.host)
        state, verdict, detail = self._draw(request)
        cost = self._cost(state, request)
        confidence = confidence_for(verdict, request.attempt)
        result = ProbeResult(
            host=request.host,
            port=request.port,
            state=state,
            verdict=verdict,
            cost_units=cost,
            confidence=confidence,
            attempt=request.attempt,
            detail=detail,
        )
        merge_stats(self._stats, result)
        return result

    def _draw(self, request: ProbeRequest) -> tuple[PortState, Verdict, str]:
        """Decide the outcome.

        Loss is applied to *positive* evidence only (an open or refused port whose
        response was dropped becomes a timeout). Turning a filtered pair into a
        success would be physically wrong; turning a success into a timeout is
        exactly what real packet loss does.
        """
        if self.scenario.is_unreachable(request.host):
            return PortState.FILTERED, Verdict.TIMEOUT, "no response from host"
        state = self.scenario.resolve(request.host, request.port)
        if state is PortState.UNDETERMINED:
            return PortState.UNDETERMINED, Verdict.UNRESOLVED, "host not in scenario"
        rng = derive_rng(self._loss_seed, f"{request.host}:{request.port}:{request.attempt}")
        if state in (PortState.OPEN, PortState.CLOSED) and rng.random() < self.scenario.loss_rate:
            return PortState.UNDETERMINED, Verdict.TIMEOUT, "probe lost (simulated loss)"
        if state is PortState.OPEN:
            return PortState.OPEN, Verdict.CONNECTED, "simulated handshake completed"
        if state is PortState.CLOSED:
            return PortState.CLOSED, Verdict.REFUSED, "simulated RST"
        return PortState.FILTERED, Verdict.TIMEOUT, "simulated drop"

    def _cost(self, state: PortState, request: ProbeRequest) -> int:
        """Billing model - the whole benchmark depends on this being sane.

        ``open``/``closed`` bill one round trip; ``filtered`` bills the capped
        timeout; ``undetermined`` (host not described by the scenario) bills half
        the timeout, matching a partial wait.
        """
        low, high = self.scenario.latency_ms
        rng = derive_rng(f"schedprobe-latency:{self.seed}", f"{self.scenario.name}:{request.host}")
        rtt = low + int(rng.random() * max(1, high - low + 1))
        if state in (PortState.OPEN, PortState.CLOSED):
            return max(1, rtt)
        capped = request.effective_timeout_s
        if state is PortState.FILTERED:
            return max(1, int(capped * 1000))
        return max(1, int(capped * 1000 * 0.5))

    # ------------------------------------------------------------------ helpers
    def truth(self, hosts: Sequence[str], ports: Sequence[int]) -> dict[tuple[str, int], PortState]:
        return self.scenario.ground_truth(hosts, ports)

    def describe(self) -> dict[str, Any]:
        return {
            "backend": self.name,
            "cost_unit": self.cost_unit,
            "scenario": self.scenario.name,
            "description": self.scenario.description,
            "hosts": len(self.scenario.hosts),
            "loss_rate": self.scenario.loss_rate,
            "latency_ms": list(self.scenario.latency_ms),
            "seed": self.seed,
        }
