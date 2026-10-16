"""Diagnostic: step a replay and compare it with the recorded frontier at every step.

python scripts/diagnose_frontier.py runs/<run-id>/evidence.jsonl
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from schedprobe.config import config_from_dict
from schedprobe.evidence import read_records
from schedprobe.frontier import CostLedger, Frontier
from schedprobe.models import ProbeResult
from schedprobe.planners import build_planner


def _pair(key: str) -> tuple[str, int]:
    host, _, port = key.rpartition(":")
    return (host, int(port))


def main(path: str) -> int:
    rows = list(read_records(path))
    header = next(r for r in rows if r.kind == "run-header")
    config = config_from_dict(dict(next(r for r in rows if r.kind == "config").data))
    hosts = tuple(str(h) for h in header.data["targets"])
    planner = build_planner(str(header.data["planner"]), hosts, tuple(config.ports), config.planner)
    planner.initialise()
    ledger = CostLedger(budget=int(header.data["budget"]))
    frontier = Frontier(planner, ledger)

    startup = next((r for r in rows if r.kind == "startup"), None)
    if startup is None:
        print("no startup record (old log format)")
        return 1
    frontier.start_with([_pair(k) for k in startup.data["pairs"]])
    print(f"startup pairs={len(startup.data['pairs'])} in_flight={len(frontier.in_flight)}")

    for record in (r for r in rows if r.kind == "probe"):
        data = record.data
        pair = (data["dispatched"]["host"], int(data["dispatched"]["port"]))
        frontier.consume(pair, data["observation"]["cost_units"])
        planner.observe(ProbeResult.from_dict(dict(data["observation"])))
        decision = data.get("decision")
        wanted = (decision["host"], int(decision["port"])) if decision else None
        peeked = planner.peek()
        extra_keys = data.get("extra_dispatched") or []
        snapshot_before = frontier.snapshot()
        _took, extra_pairs = frontier.admit(
            wanted, dispatched=bool(data.get("decision_dispatched", True)), extra=extra_keys
        )
        snapshot_after = frontier.snapshot()
        recorded = sorted(data.get("inflight_pairs") or [])
        mark = "OK " if snapshot_after == recorded else "DIF"
        print(
            f"seq {record.seq}: ran={pair} peeked={peeked} decision={wanted} "
            f"extras={len(extra_keys)} admitted={len(extra_pairs)} "
            f"in_flight={len(frontier.in_flight)} [{mark}]"
        )
        if snapshot_after != recorded:
            before_set = set(snapshot_before)
            after_set = set(snapshot_after)
            rec_set = set(recorded)
            print(f"    before={sorted(before_set)[:3]}...")
            print(f"    missing_from_replay={sorted(rec_set - after_set)[:5]}")
            print(f"    extra_in_replay={sorted(after_set - rec_set)[:5]}")
            print(f"    extras_head={extra_keys[:3]}")
            return 1
    print("frontier reconstruction matched every record")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
