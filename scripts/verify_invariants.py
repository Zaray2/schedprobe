import sys, asyncio, logging, shutil, tempfile; sys.path.insert(0,'src')
OUT_DIR = tempfile.mkdtemp(prefix="schedprobe-invariants-")
logging.basicConfig(level=logging.ERROR)
from schedprobe.backends.fake import FakeBackend, builtin_scenarios
from schedprobe.config import ScanConfig, PlannerConfig, NetworkConfig
from schedprobe.engine import ScanEngine
from schedprobe.evidence import read_records, verify_chain
from schedprobe.replay import replay_chain

bad = []
for name, scenario in sorted(builtin_scenarios().items()):
    hosts = tuple(sorted(scenario.hosts))
    ports = tuple(range(1,65)) if name == "segmented-sweep" else (22,80,443,3306,6379,8080,8443)
    for mode in ("defer", "drop"):
        for budget in (15000, 150000):
            for kind in ("adaptive", "fixed", "random"):
                pc = PlannerConfig(kind=kind, seed=1337, cost_budget=budget, prune_mode=mode, verify_heap=True)
                cfg = ScanConfig(targets=hosts, ports=ports, backend="fake", planner=pc,
                                 network=NetworkConfig(concurrency=64, max_hosts=128, max_ports=1024)).validate()
                eng = ScanEngine(cfg, backend=FakeBackend(scenario=scenario, allow=list(hosts), config=cfg),
                                 out_dir=OUT_DIR, run_id=f"{name}-{mode}-{budget}-{kind}")
                run = asyncio.run(eng.run())
                rows = [r for r in read_records(run.evidence_path) if r.kind == "probe"]
                notes = []
                if any(r.data["cost_spent"] + r.data["reserved_units"] > r.data["budget"] for r in rows):
                    notes.append("BUDGET")
                if any(len(r.data["inflight_pairs"]) > cfg.network.concurrency for r in rows):
                    notes.append("INFLIGHT")
                if not verify_chain(run.evidence_path).ok: notes.append("CHAIN")
                rep = replay_chain(run.evidence_path)
                if not rep.ok: notes.append(f"REPLAY({len(rep.divergences)})")
                if run.manifest["probe_errors"]: notes.append("PROBE_ERRORS")
                if notes: bad.append((name, mode, budget, kind, notes))
shutil.rmtree(OUT_DIR, ignore_errors=True)
print("checked 6 scenarios x 2 modes x 2 budgets x 3 planners")
print("violations:", bad if bad else "none")
sys.exit(1 if bad else 0)
