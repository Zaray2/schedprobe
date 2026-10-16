"""Diagnostic: compare plan_next() against the log's next_decision, using recorded observations.

Reproduces, without any concurrency, the exact observation sequence of a run and
prints where the planner's answer stops matching the log.

    python scripts/diagnose_trace.py runs/<run-id>/evidence.jsonl
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from schedprobe.config import config_from_dict
from schedprobe.evidence import read_records
from schedprobe.models import ProbeResult
from schedprobe.planners import build_planner


def main(path: str) -> int:
    records = list(read_records(path))
    header = next(r for r in records if r.kind == "run-header")
    config = config_from_dict(dict(next(r for r in records if r.kind == "config").data))
    hosts = tuple(str(h) for h in header.data["targets"])
    planner = build_planner(str(header.data["planner"]), hosts, tuple(config.ports), config.planner)
    planner.initialise()

    for record in records:
        if record.kind != "probe":
            continue
        decision = record.data["decision"]
        pair = (str(decision["host"]), int(decision["port"]))
        fresh = planner.plan_next(pair)
        print(
            f"order={record.data['dispatch_order']:<3} pair={pair} "
            f"recorded_reason={decision['reason']:<22} fresh_reason={fresh.reason:<22} "
            f"recorded_prio={decision['priority']:<12} fresh_prio={fresh.priority:<12} "
            f"live={planner.live_count()}"
        )
        planner.take(pair)
        planner.observe(ProbeResult.from_dict(dict(record.data["observation"])))
        nxt = record.data.get("next_decision")
        if nxt:
            peeked = planner.peek()
            want = (str(nxt["host"]), int(nxt["port"]))
            marker = "OK " if peeked == want else "DIF"
            peeked_score = planner.score(*peeked) if peeked else None
            print(
                f"      next recorded={want} peeked={peeked} [{marker}]"
                f" recorded_prio={nxt['priority']} peeked_prio={peeked_score}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
