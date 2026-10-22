"""FuzzLab: scheduling research on top of SchedProbe's budget and evidence machinery.

The point of this subpackage is narrow and stated up front, because it is easy for a
fuzzing side-project to sprawl: **it studies which corpus entry gets fuzzed next**, not how
mutation works, not how coverage instrumentation works, and not how a fuzzer is built. The
engine is AFL++ and the target is a real parser; both are other people's work and are used
as-is. What is ours is the admission policy that decides which seeds receive the budget, and
the measurement that says whether that policy is better than doing nothing.

Two pieces of SchedProbe are reused rather than reinvented:

* **the hard budget cap** - a fuzzing campaign is stopped by a budget that is checked
  before the work is spent, never after, for the same reason the probe scheduler does it:
  an overshoot discovered afterwards cannot be undone.
* **the hash-chained evidence log** - every experiment run records its configuration, its
  results and its artefacts into an append-only chain, so a reported number can be traced
  back to the run that produced it and tampering is at least detectable.

What is deliberately *not* reused: the probe planner itself. TCP probing ranks hosts, and a
fuzzer ranks seeds; forcing one abstraction onto both would have produced a worse scheduler
for each and a weaker claim.
"""

from __future__ import annotations

from .arms import ARMS, Arm, arm_by_name
from .dedup import CrashRecord, crash_signature, dedup_crashes
from .model import CampaignResult, Experiment, RunStats
from .stats import parse_fuzzer_stats, read_fuzzer_stats

__all__ = [
    "ARMS",
    "Arm",
    "CampaignResult",
    "CrashRecord",
    "Experiment",
    "RunStats",
    "arm_by_name",
    "crash_signature",
    "dedup_crashes",
    "parse_fuzzer_stats",
    "read_fuzzer_stats",
]
