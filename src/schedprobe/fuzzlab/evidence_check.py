"""Whether the scheduler actually ran, checked before any result is believed.

Two research rounds were lost to the same mistake: an intervention that was not running,
measured as though it were. The instruments that should have caught it did not, because
nothing asked the question "how many times did the policy get to make a decision?".

This module asks it, and it answers with an error rather than a statistic. A campaign where
the scheduler fired zero times did not produce a weak result - it produced no result, and the
difference between those two is the difference between a finding and a fabrication.
"""

from __future__ import annotations

from dataclasses import dataclass


class InertInterventionError(RuntimeError):
    """The scheduler did not fire enough to have influenced anything.

    Raised instead of returning a number, because a number - even zero - reads as evidence.
    """


@dataclass(frozen=True, slots=True)
class InterventionEvidence:
    """How often the policy under test was actually consulted during a campaign."""

    arm: str
    execs: int
    decisions: int
    admitted: int
    admit_ratio: float

    @property
    def decision_ratio(self) -> float:
        """Decisions per execution.

        A per-execution scheduler such as the FuzzLab loop makes one decision per execution,
        so this is 1.0. A coarser hook can legitimately be far below 1.0, but it has to be
        above the floor passed to :func:`require_intervention_fired`.
        """
        if self.execs <= 0:
            return 0.0
        return self.decisions / self.execs

    def to_dict(self) -> dict[str, object]:
        return {
            "arm": self.arm,
            "execs": self.execs,
            "decisions": self.decisions,
            "admitted": self.admitted,
            "admit_ratio": round(self.admit_ratio, 4),
            "decision_ratio": round(self.decision_ratio, 6),
        }


def require_intervention_fired(
    evidence: InterventionEvidence, *, minimum_ratio: float = 0.01
) -> InterventionEvidence:
    """Return ``evidence`` if the scheduler fired meaningfully, else raise.

    ``minimum_ratio`` is decisions per execution. The default 0.01 means the policy had to be
    consulted at least once in a hundred executions - a deliberately lenient floor, because
    the point is to catch "the plugin never loaded", not to police the granularity of a
    legitimate hook.

    Also rejects a policy that never admits anything. In AFL++ that state does not merely
    score badly: an all-reject queue cycle makes the fuzzer conclude it has no work and exit,
    and the resulting low execution count is then easy to misread as a performance result.
    """
    if evidence.execs <= 0:
        raise InertInterventionError(
            f"arm {evidence.arm!r} recorded {evidence.execs} executions, so there is nothing "
            "to measure the intervention against"
        )
    if evidence.decision_ratio < minimum_ratio:
        raise InertInterventionError(
            f"the scheduling policy for arm {evidence.arm!r} did not fire: "
            f"{evidence.decisions} decisions across {evidence.execs} executions "
            f"({evidence.decision_ratio:.5f} per execution, floor {minimum_ratio}). "
            "A campaign in this state is invalid, not an arm that performed badly - check "
            "that the plugin loaded and that its hooks are actually being called."
        )
    if evidence.admitted <= 0:
        raise InertInterventionError(
            f"the scheduling policy for arm {evidence.arm!r} admitted nothing across "
            f"{evidence.decisions} decisions; a policy that rejects the whole queue is not "
            "scheduling, and in AFL++ it makes the fuzzer exit early"
        )
    return evidence
