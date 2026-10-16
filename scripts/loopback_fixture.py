"""Local fixture: bind a few TCP ports on loopback, then probe them with the real backend.

This is the end-to-end proof that the real backend works: a listener started here, a
scan of that listener by the shipped code, and an assertion on the result. No external
target is involved.
"""

from __future__ import annotations

import socket
import sys
import threading
import time

sys.path.insert(0, "src")

import asyncio

from schedprobe.config import NetworkConfig, PlannerConfig, ScanConfig
from schedprobe.engine import ScanEngine
from schedprobe.evidence import verify_chain
from schedprobe.replay import replay_chain


def listener(port: int, banner: bytes = b"") -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)

    def loop():
        srv.settimeout(0.5)
        end = time.time() + 25
        while time.time() < end:
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                if banner:
                    conn.sendall(banner)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv


open_ports = (18711, 18712)
srvs = [listener(p, b"SSH-2.0-test\r\x1b]0;evil\x07") for p in open_ports]
time.sleep(0.3)

ports = (18711, 18712, 18713, 18714)  # 18713/18714 are not listening
cfg = ScanConfig(
    targets=("127.0.0.1",),
    ports=ports,
    backend="real",
    run_label="loopback-fixture",
    planner=PlannerConfig(kind="adaptive", seed=5, cost_budget=20000),
    network=NetworkConfig(
        concurrency=4, base_timeout_s=0.4, min_timeout_s=0.15, max_timeout_s=1.5, rate_limit_pps=0
    ),
).validate()

engine = ScanEngine(cfg, out_dir="runs-fixture", grab_banner=True)
run = asyncio.run(engine.run())

print("elapsed_s:", round(run.summary.elapsed_s, 3), "cost(ms):", run.summary.cost_spent)
found: dict[int, tuple[str, str, int, str]] = {}
target_host = str(cfg.targets[0])
for (_scanned_host, result_port), result in sorted(run.results.items()):
    found[result_port] = (result.state.value, result.verdict.value, result.cost_units, result.detail)
for wanted_port in ports:
    print(f"  {target_host}:{wanted_port} -> {found.get(wanted_port)}")

ok_open = all(found.get(p, ("",))[0] == "open" for p in open_ports)
closed_or_filtered = all(found.get(p, ("",))[0] in ("closed", "filtered") for p in (18713, 18714))
chain = verify_chain(run.evidence_path)
replay = replay_chain(run.evidence_path)
print("open ports detected:", ok_open)
print("unbound ports not reported open:", closed_or_filtered)
print("chain ok:", chain.ok, "| replay ok:", replay.ok, "| divergences:", len(replay.divergences))
banner = found.get(18711, ("", "", 0, ""))[3]
print("banner sanitised (ESC stripped):", "\\x1b" not in banner and "evil" in banner)
for s in srvs:
    s.close()
sys.exit(0 if (ok_open and closed_or_filtered and chain.ok and replay.ok) else 1)
