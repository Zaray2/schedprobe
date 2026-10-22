"""The experimental arms, defined once so the runner and the report cannot disagree.

Every arm runs the same binary, the same target, the same AFL++ power schedule and the same
budget. The only difference is the environment passed to the scheduler library, and for the
stock arm, the absence of the library at all. That is what makes the comparison a
comparison of scheduling rather than of build configuration.

The arms exist to separate two variables that are easy to conflate:

* ``static`` and ``feedback`` are the **ablation**. If the combined policy wins, one of
  these two may be doing all the work, and without them the report cannot say which.
* ``all`` exists so that *having a plugin loaded at all* is not mistaken for a scheduling
  effect. It goes through the same code path as the experiment arm and admits everything.
   If ``all`` and ``stock`` differ materially, the harness is measuring itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Arm:
    """One experimental condition."""

    name: str
    #: ``FUZZLAB_MODE`` value, or ``None`` to run with no plugin loaded at all.
    mode: str | None
    #: Human-readable statement of what this arm is for, used verbatim in the report.
    role: str
    #: Env overrides for the plugin; kept explicit so the report can print them.
    env: dict[str, str] = field(default_factory=dict)

    @property
    def uses_plugin(self) -> bool:
        return self.mode is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "mode": self.mode,
            "role": self.role,
            "uses_plugin": self.uses_plugin,
            "env": dict(self.env),
        }


#: Order matters for the report: baselines first, then the experiment, then the ablation.
ARMS: tuple[Arm, ...] = (
    Arm(
        name="stock",
        mode=None,
        role=(
            "Baseline B: AFL++ exactly as shipped, no plugin. This is the engine's own "
            "scheduling, which is what a practitioner would get with no extra work."
        ),
    ),
    Arm(
        name="all",
        mode="all",
        role=(
            "Baseline A: the plugin loaded but admitting every entry. Same code path as the "
            "experiment arm, so a difference between this and stock would be harness "
            "overhead rather than scheduling."
        ),
    ),
    Arm(
        name="static",
        mode="static",
        role="Ablation: structural features of the seed only, no queue feedback.",
        env={"FUZZLAB_W_STATIC": "1.0", "FUZZLAB_W_FEEDBACK": "0.0"},
    ),
    Arm(
        name="feedback",
        mode="feedback",
        role="Ablation: queue recency and starvation only, no static analysis.",
        env={"FUZZLAB_W_STATIC": "0.0", "FUZZLAB_W_FEEDBACK": "1.0"},
    ),
    Arm(
        name="full",
        mode="full",
        role="Experiment C: static analysis combined with queue feedback.",
        env={"FUZZLAB_W_STATIC": "1.0", "FUZZLAB_W_FEEDBACK": "1.0"},
    ),
)

_BY_NAME = {arm.name: arm for arm in ARMS}


def arm_by_name(name: str) -> Arm:
    """Look up an arm, with an error that lists the valid names."""
    try:
        return _BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown arm {name!r}; known arms: {sorted(_BY_NAME)}") from None
