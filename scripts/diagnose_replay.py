"""Diagnostic: compare a replayed planner against the recorded decision log step by step.

Not part of the shipped test-suite; a debugging aid for exactly the kind of
divergence that ``schedprobe replay`` reports. Usage::

    python scripts/diagnose_replay.py runs/<run-id>/evidence.jsonl
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

    print(f"planner={planner.planner_name} hosts={len(hosts)} ports={len(config.ports)}")
    print(f"initial live={planner.live_count()}")

    step = 0
    for record in records:
        if record.kind != "probe":
            continue
        step += 1
        decision = record.data["decision"]
        pair = (str(decision["host"]), int(decision["port"]))
        observation = ProbeResult.from_dict(dict(record.data["observation"]))
        recorded_next = record.data.get("next_decision")
        recorded_live = int(record.data.get("live_pairs", -1))
        recorded_timeout = decision.get("timeout_s")

        peeked = planner.peek()
        replayed_timeout = planner.timeout_for(pair) if peeked == pair else None
        print(
            f"\nstep {step} slot={record.data.get('dispatch_order')} "
            f"recorded={pair} peeked={peeked} live_recorded={recorded_live} "
            f"live_replayed={planner.live_count()}"
        )
        if (
            recorded_timeout is not None
            and replayed_timeout is not None
            and abs(float(recorded_timeout) - float(replayed_timeout)) > 1e-6
        ):
            print(
                f"  TIMEOUT DIFF recorded={float(recorded_timeout):.6f} "
                f"replayed={float(replayed_timeout):.6f} "
                f"rtt_replayed={planner.rtt.snapshot().get(pair[0])}"
            )
        planner.take(pair)
        updates, _changes = planner.observe(observation)
        recorded_updates = record.data.get("rank_updates", [])
        print(
            f"  observation={observation.state.value}/{observation.verdict.value} "
            f"cost={observation.cost_units}"
        )
        print(f"  rank_updates recorded={len(recorded_updates)} replayed={len(updates)}")
        if len(recorded_updates) != len(updates):
            rec = {(u["host"], u["port"]) for u in recorded_updates}
            rep = {(u.host, u.port) for u in updates}
            print(f"    only-recorded={sorted(rec - rep)[:6]}")
            print(f"    only-replayed={sorted(rep - rec)[:6]}")
        if recorded_next:
            rp = planner.peek()
            want = (str(recorded_next["host"]), int(recorded_next["port"]))
            flag = "OK" if rp == want else "MISMATCH"
            print(f"  next recorded={want} replayed={rp} [{flag}]")
            if rp != want:
                print(f"    recorded priority={recorded_next.get('priority')}")
                print(f"    replayed priority={planner.score(*rp) if rp else None}")
                print(f"    segment recorded={recorded_next.get('host')}")
                for seg, state in sorted(planner.book.segments.items()):
                    print(
                        f"      {seg}: planned={state.planned} open={state.open_count} "
                        f"closed={state.closed_count} filtered={state.filtered_count} "
                        f"ema={state.confidence_ema} health={state.health_score()} "
                        f"pruned={state.pruned}"
                    )
                if rp:
                    print(f"    replayed target segment={planner.book.of(rp[0]).segment}")
                break
        if not record.data.get("next_decision"):
            print("  (no next decision recorded; sweep ended)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "runs/latest/evidence.jsonl"))
