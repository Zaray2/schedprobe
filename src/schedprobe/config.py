"""Typed configuration: defaults, file loading (TOML/JSON), and validation.

The config object is the single source of truth for a scan. It is recorded
verbatim in the evidence log header, so a run can be reproduced from the log
alone without the original command line.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import ConfigError, TargetValidationError
from .models import normalize_target
from .targets import expand_targets, validate_targets

__all__ = [
    "PlannerConfig",
    "NetworkConfig",
    "OutputConfig",
    "SafetyConfig",
    "ScanConfig",
    "default_config",
    "load_config",
    "config_from_dict",
    "config_to_dict",
]

PLANNER_KINDS = ("adaptive", "fixed", "random", "fixed-longtimeout")
BACKEND_KINDS = ("fake", "real")


@dataclass(slots=True)
class PlannerConfig:
    """Knobs of the scheduling policy.

    Defaults are chosen for 'safe on a corporate /16 with mixed filtering': a
    modest budget, timeouts validated against observed refusals, and pruning only
    after several consecutive cheap failures inside one segment.
    """

    kind: str = "adaptive"
    seed: int = 1337
    cost_budget: int = 4000
    reserved_ratio: float = 0.15
    prefix_len: int = 24
    prune_after_consecutive_timeouts: int = 3
    prune_min_planned: int = 3
    # What "pruning" means. ``defer`` (default) stops *prioritising* a dead segment but
    # leaves its unprobed pairs available, so a generous budget still gets the recall
    # back. ``drop`` removes them from the frontier entirely, which is cheaper and was
    # the original behaviour - the benchmark showed it loses recall on segments that
    # are mostly-but-not-entirely dead (``blackhole-segment``: 60% vs 100%).
    prune_mode: str = "defer"
    # Multiplier applied to a deferred segment's score. Large enough to sink it behind
    # every live segment, small enough that its pairs are still probed once the live
    # segments are exhausted and budget remains.
    deferred_penalty: float = 2.0
    # Total probes per inconclusive pair is ``1 + confirm_min_attempts``. The
    # default of 1 means 'one retry': enough to separate a dropped packet from a
    # filtered port, cheap enough not to dominate a budget (see the benchmark
    # scenario ``wide-sweep``, where the old value of 2 measurably hurt).
    confirm_min_attempts: int = 1
    confirm_timeout_multiplier: float = 2.5
    confidence_threshold: float = 0.7
    # Confirmations are only worth their budget where the result is surprising. A segment
    # whose probes are already mostly dropped has told us what it is going to do; a
    # segment that answers promptly and then times out has not. Measured on
    # ``blackhole-segment``: confirming everything cost ~2x and cut recall from 100% to
    # 60% at the same budget; gating on this ratio restored it.
    confirm_max_drop_ratio: float = 0.5
    timeout_penalty: float = 1.0
    stale_window: int = 0
    # Budget accounting slot, in the backend's cost unit (milliseconds for the real
    # backend). Every dispatched probe reserves exactly this much and releases the
    # difference when it finishes. Keeping it a constant is deliberate: the first
    # implementation reserved the *adaptive timeout*, which made the budget rule a
    # function of the RTT estimator and therefore unreproducible offline (the replay
    # could not re-derive why a probe was refused). Detection quality stays with the
    # timeout; budget accounting is a fixed integer count. Set 0 to fall back to the
    # old behaviour, which is kept only so the regression is documented in tests.
    budget_slot_ms: int = 600
    # Off by default: O(n) invariant check in Planner.peek (see its docstring). Turning
    # it on costs a linear scan per dispatch and turns a mis-ordered frontier into a
    # logged warning instead of a silent scheduling difference.
    verify_heap: bool = False

    def validate(self) -> None:
        if self.kind not in PLANNER_KINDS:
            raise ConfigError(
                f"planner.kind must be one of {PLANNER_KINDS}", value=self.kind
            )
        if self.cost_budget < 1:
            raise ConfigError("planner.cost_budget must be >= 1", value=self.cost_budget)
        if not 0.0 <= self.reserved_ratio < 1.0:
            raise ConfigError(
                "planner.reserved_ratio must be in [0, 1)", value=self.reserved_ratio
            )
        if not 8 <= self.prefix_len <= 32:
            raise ConfigError("planner.prefix_len must be within [8, 32]", value=self.prefix_len)
        if self.prune_after_consecutive_timeouts < 1:
            raise ConfigError("planner.prune_after_consecutive_timeouts must be >= 1")
        if self.prune_mode not in ("defer", "drop"):
            raise ConfigError("planner.prune_mode must be 'defer' or 'drop'", value=self.prune_mode)
        if self.deferred_penalty <= 0:
            raise ConfigError("planner.deferred_penalty must be > 0")
        if self.confirm_min_attempts < 1:
            raise ConfigError("planner.confirm_min_attempts must be >= 1")
        if self.confirm_timeout_multiplier < 1.0:
            raise ConfigError("planner.confirm_timeout_multiplier must be >= 1.0")
        if not 0.0 < self.confidence_threshold <= 1.0:
            raise ConfigError("planner.confidence_threshold must be in (0, 1]")
        if not 0.0 <= self.confirm_max_drop_ratio <= 1.0:
            raise ConfigError("planner.confirm_max_drop_ratio must be within [0, 1]")
        if self.timeout_penalty < 0:
            raise ConfigError("planner.timeout_penalty must be >= 0")
        if self.budget_slot_ms < 0:
            raise ConfigError("planner.budget_slot_ms must be >= 0")


@dataclass(slots=True)
class NetworkConfig:
    """Probe timing. ``*_timeout_s`` values are validated against reality at runtime."""

    concurrency: int = 128
    base_timeout_s: float = 0.6
    min_timeout_s: float = 0.15
    max_timeout_s: float = 3.0
    max_attempts: int = 2
    max_hosts: int = 4096
    max_ports: int = 4096
    rate_limit_pps: float = 0.0
    resolve_timeout_s: float = 2.0

    def validate(self) -> None:
        if not 1 <= self.concurrency <= 4096:
            raise ConfigError("network.concurrency must be within [1, 4096]", value=self.concurrency)
        if not 0 < self.min_timeout_s <= self.base_timeout_s <= self.max_timeout_s:
            raise ConfigError(
                "require 0 < network.min_timeout_s <= base_timeout_s <= max_timeout_s",
                min=self.min_timeout_s,
                base=self.base_timeout_s,
                max=self.max_timeout_s,
            )
        if not 1 <= self.max_attempts <= 10:
            raise ConfigError("network.max_attempts must be within [1, 10]", value=self.max_attempts)
        if self.rate_limit_pps < 0:
            raise ConfigError("network.rate_limit_pps must be >= 0")
        if self.resolve_timeout_s <= 0:
            raise ConfigError("network.resolve_timeout_s must be > 0")


@dataclass(slots=True)
class OutputConfig:
    """Where artifacts go and how much detail they carry.

    ``replay_only`` exists so that ``replay`` can reuse the very same config object
    while refusing to touch the network.
    """

    out_dir: str = "runs"
    redact: bool = False
    include_closed: bool = False
    max_results: int = 0
    replay_only: bool = False
    format: str = "table"

    def validate(self) -> None:
        if self.format not in ("table", "json", "jsonl", "csv"):
            raise ConfigError("output.format must be table|json|jsonl|csv", value=self.format)
        if self.max_results < 0:
            raise ConfigError("output.max_results must be >= 0")
        if not self.out_dir:
            raise ConfigError("output.out_dir must not be empty")


@dataclass(slots=True)
class SafetyConfig:
    """Scope guards. See ``targets.py`` for what each one actually enforces."""

    allow_public: bool = False
    allow_private: bool = True
    allow_loopback: bool = True
    allow_dns: bool = True
    allow_ulist: bool = True
    max_span_ratio: float = 1.0

    def validate(self) -> None:
        if not 0.0 < self.max_span_ratio <= 1.0:
            raise ConfigError("safety.max_span_ratio must be in (0, 1]")


@dataclass(slots=True)
class ScanConfig:
    """Top-level scan configuration."""

    targets: tuple[str, ...] = ("127.0.0.1",)
    ports: tuple[int, ...] = (22, 80, 443, 3306, 6379, 8080, 8443)
    backend: str = "fake"
    # Simulation scenario for the ``fake`` backend. Kept in the config (rather than
    # CLI-only) so an example file is self-contained and reproducible by construction.
    scenario: str = ""
    run_label: str = ""
    notes: str = ""
    planner: PlannerConfig = field(default_factory=PlannerConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)

    # ---------------------------------------------------------------- validate
    def validate(self) -> "ScanConfig":
        """Validate every sub-section and normalize targets/ports in place.

        Raises :class:`ConfigError` or :class:`TargetValidationError`; never
        silently repairs invalid input, because a scan that quietly changes scope
        is worse than a scan that refuses to start.
        """
        if self.backend not in BACKEND_KINDS:
            raise ConfigError(f"backend must be one of {BACKEND_KINDS}", value=self.backend)
        if self.scenario:
            from .backends.fake import builtin_scenarios

            if self.scenario not in builtin_scenarios():
                raise ConfigError(
                    "unknown simulation scenario",
                    scenario=self.scenario,
                    known=sorted(builtin_scenarios()),
                )
        self.planner.validate()
        self.network.validate()
        self.output.validate()
        self.safety.validate()

        if not self.targets:
            raise TargetValidationError("no targets supplied")
        if not self.ports:
            raise TargetValidationError("no ports supplied")

        normalized: list[str] = []
        for raw in self.targets:
            if not isinstance(raw, str):
                raise TargetValidationError("targets must be strings", value=repr(raw))
            try:
                normalized.append(normalize_target(raw))
            except ValueError as exc:
                raise TargetValidationError(f"bad target {raw!r}: {exc}") from exc
        self.targets = tuple(dict.fromkeys(normalized))

        for port in self.ports:
            if not isinstance(port, int) or isinstance(port, bool):
                raise TargetValidationError("ports must be integers", value=repr(port))
            if not 1 <= port <= 65535:
                raise TargetValidationError("port out of range 1-65535", value=port)
        self.ports = tuple(dict.fromkeys(self.ports))

        if len(self.targets) > self.network.max_hosts:
            raise TargetValidationError(
                "expanded target count exceeds network.max_hosts",
                count=len(self.targets),
                limit=self.network.max_hosts,
            )
        if len(self.ports) > self.network.max_ports:
            raise TargetValidationError(
                "port count exceeds network.max_ports",
                count=len(self.ports),
                limit=self.network.max_ports,
            )

        # Scope guard. CIDR targets are expanded *first* so the public/private decision
        # is made about the concrete addresses that will actually be probed - checking
        # the "a.b.c.d/24" literal instead would let a CIDR spanning private and public
        # space through on the strength of its first octet. This also keeps the CLI's
        # documented "-t HOST|CIDR" behaviour working; an earlier revision ran the guard
        # over the unexpanded list and rejected every CIDR with
        # "hostname does not look like an RFC 1123 name".
        expanded = expand_targets(self.targets, self.network.max_hosts)
        validate_targets(list(expanded), self.safety, self.network.max_hosts)
        if self.safety.max_span_ratio < 1.0:
            total_pairs = len(expanded) * len(self.ports)
            if self.planner.cost_budget < total_pairs * self.safety.max_span_ratio:
                raise ConfigError(
                    "cost_budget is too small for the requested span under safety.max_span_ratio",
                    pairs=total_pairs,
                    budget=self.planner.cost_budget,
                    ratio=self.safety.max_span_ratio,
                )
        return self

    # -------------------------------------------------------------- serialize
    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["targets"] = list(self.targets)
        payload["ports"] = list(self.ports)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ScanConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(payload) - known
        if unknown:
            raise ConfigError("unknown configuration keys", keys=sorted(unknown))
        data = dict(payload)
        # NOTE: the defaults must come from an *instance*. ``ScanConfig`` is a slots
        # dataclass, so ``cls.targets`` is a ``member_descriptor``, and ``tuple(...)``
        # over it raises TypeError - which is exactly the bug that made
        # ``schedprobe scan -t HOST -p PORT`` (no --config) crash before any network
        # activity. ``tests/test_config.py`` pins this.
        defaults = cls()
        data["targets"] = tuple(data.get("targets", defaults.targets))
        data["ports"] = tuple(int(p) for p in data.get("ports", defaults.ports))
        data["planner"] = _sub(PlannerConfig, data.get("planner"))
        data["network"] = _sub(NetworkConfig, data.get("network"))
        data["output"] = _sub(OutputConfig, data.get("output"))
        data["safety"] = _sub(SafetyConfig, data.get("safety"))
        return cls(**data)


def _sub(cls: type, payload: Mapping[str, Any] | None) -> Any:
    if payload is None:
        return cls()
    if not isinstance(payload, Mapping):
        raise ConfigError(f"{cls.__name__} section must be a table/object")
    known = {f.name for f in fields(cls)}
    unknown = set(payload) - known
    if unknown:
        raise ConfigError(f"unknown keys in {cls.__name__}", keys=sorted(unknown))
    return cls(**dict(payload))


def default_config(**overrides: Any) -> ScanConfig:
    """Build a validated config from defaults plus keyword overrides."""
    cfg = ScanConfig(**overrides)
    return cfg.validate()


def config_from_dict(payload: Mapping[str, Any]) -> ScanConfig:
    return ScanConfig.from_dict(payload).validate()


def config_to_dict(cfg: ScanConfig) -> dict[str, Any]:
    return cfg.to_dict()


def load_config(path: str | Path | None = None, overrides: Mapping[str, Any] | None = None) -> ScanConfig:
    """Load a TOML/JSON config file (optional) and apply flat overrides.

    ``overrides`` uses dotted keys such as ``{"planner.cost_budget": 500}`` to
    match the CLI, which is the only caller.
    """
    payload: dict[str, Any] = {}
    if path is not None:
        cfg_path = Path(path)
        if not cfg_path.is_file():
            raise ConfigError("config file not found", path=str(cfg_path))
        raw = cfg_path.read_bytes()
        try:
            if cfg_path.suffix.lower() == ".json":
                payload = json.loads(raw.decode("utf-8"))
            elif cfg_path.suffix.lower() in (".toml", ".tml"):
                payload = tomllib.loads(raw.decode("utf-8"))
            else:
                raise ConfigError(
                    "unsupported config extension (expected .toml or .json)",
                    path=str(cfg_path),
                )
        except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"failed to parse config: {exc}", path=str(cfg_path)) from exc
        if not isinstance(payload, Mapping):
            raise ConfigError("config root must be a table/object", path=str(cfg_path))

    for dotted, value in (overrides or {}).items():
        if value is None:
            continue
        section, _, leaf = dotted.partition(".")
        if not leaf:
            payload[section] = value
        else:
            block = payload.setdefault(section, {})
            if not isinstance(block, Mapping):
                raise ConfigError(f"config section {section!r} is not a table/object")
            block = dict(block)
            block[leaf] = value
            payload[section] = block

    return config_from_dict(payload)


def coerce_sequence(values: Sequence[str] | str | None) -> tuple[str, ...]:
    """Turn CLI list arguments into a normalized tuple."""
    if values is None:
        return ()
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return tuple(out)
