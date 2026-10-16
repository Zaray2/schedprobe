"""Injected packet loss and delay, because loopback cannot produce either.

This is the last gap the loopback tests leave, and a reviewer named it before I did:

    "needs a non-loopback host I own" describes a priority problem as a resource
    problem, and a resource problem sounds better, because it is not "I did not
    think of it" but "I could not do it".

They were right. A network namespace plus a veth pair plus `tc netem` produces loss, delay
and a genuine timeout on one machine with no privileges beyond the ability to create a
namespace - which a CI runner has and the Windows host this repository was authored on does
not. So this file is written to run where it can and to say so where it cannot, rather than
to be absent.

**Why it matters specifically.** A TCP connect yields `FILTERED` only when packets are
*dropped* rather than answered or refused. On loopback an unopened port is either reset or
answered by the local stack, so the `FILTERED` verdict - and therefore the whole timeout
path, the RTT estimator, and the confirmation logic that fires on inconclusive results -
had no real-socket coverage at all. It was exercised only by the simulator.

**Topology.**

    host namespace                    new namespace
    10.200.1.1/24  <--- veth0  veth1 --->  10.200.1.2/24

    no qdisc        -> SYN reaches the namespace, nothing listens, RST comes back -> CLOSED
    netem loss 100% -> SYN is dropped on the way out                             -> FILTERED
    netem delay     -> the connect takes measurably longer, and the tool must not
                       mistake slowness for absence

**Failure policy.** Setup failure skips with the measured reason, because an environment
without `ip` or `tc` cannot be blamed on the code. An assertion failure after successful
setup fails loudly, because that is a real disagreement. The distinction matters: a test
that skips everywhere would be worse than no test, so the skip reason is always the
command that failed and what it said.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from schedprobe.backends.real import RealTcpBackend
from schedprobe.config import NetworkConfig, PlannerConfig, ScanConfig
from schedprobe.engine import ScanEngine
from schedprobe.models import PortState, ProbeResult, Verdict

from .tiers import TIER_ORACLE, tier

NAMESPACE = "schedprobe-netem"
HOST_ADDRESS = "10.200.1.1"
PEER_ADDRESS = "10.200.1.2"
VETH_HOST = "schedprobe-veth0"
VETH_PEER = "schedprobe-veth1"


class _SetupError(RuntimeError):
    """Raised with the failing command and its output, so a skip can explain itself."""


def _run(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command, prefixing ``sudo -n`` when this process is not already root."""
    prefix = _as_root()
    proc = subprocess.run([*prefix, *argv], capture_output=True, text=True, check=False, timeout=30)
    if check and proc.returncode != 0:
        raise _SetupError(
            f"{' '.join(prefix + list(argv))!r} exited {proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:200]}"
        )
    return proc


def _require(command: str) -> None:
    if shutil.which(command) is None:
        raise _SetupError(f"the {command!r} command is not available on this host")


def _as_root() -> list[str]:
    """Prefix for commands that need root, or nothing when already root.

    CI runners are not root but have passwordless sudo; the authoring host is Windows and
    never reaches this code, because ``_require`` rejects it first.
    """
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        return ["sudo", "-n"]
    return []


def _teardown() -> None:
    """Best-effort cleanup. Never raises, because it runs from a finally block."""
    for argv in (
        ("ip", "netns", "del", NAMESPACE),
        ("ip", "link", "del", VETH_HOST),
    ):
        try:
            subprocess.run([*_as_root(), *argv], capture_output=True, text=True, check=False, timeout=30)
        except OSError:
            # The command does not exist on this host (Windows), or the spawn failed.
            # Cleanup runs from a finally block and is best-effort by definition, so a
            # missing `ip` here must not turn a skip into an error.
            return


@tier(TIER_ORACLE)
class TestInjectedNetworkConditions(unittest.TestCase):
    """Real loss and real delay on a real (non-loopback) path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reason: str | None = None
        try:
            _setup_topology()
        except _SetupError as exc:
            cls.reason = str(exc)
            _teardown()
        except Exception as exc:  # pragma: no cover - unexpected environment shape
            cls.reason = f"{exc.__class__.__name__}: {exc}"
            _teardown()

    @classmethod
    def tearDownClass(cls) -> None:
        _teardown()

    def setUp(self) -> None:
        if self.reason:
            self.skipTest(self.reason)
        # Each test starts from a clean qdisc state, so one test cannot leak loss into the
        # next - the failure mode that would make these results meaningless.
        _clear_qdisc()

    def tearDown(self) -> None:
        if not self.reason:
            _clear_qdisc()

    # ------------------------------------------------------------------ the tests

    def test_a_refusal_travels_across_a_veth_pair(self) -> None:
        # Baseline: without any qdisc the SYN reaches the peer namespace, nothing is
        # listening there, and the RST comes back. This is the outcome loopback cannot
        # produce on the authoring host, and it is the control for the loss test below.
        result = self._probe(port=9)
        self.assertIs(
            result.state,
            PortState.CLOSED,
            f"expected a refusal across the veth pair, got {result.state.value} ({result.verdict.value})",
        )
        self.assertIn(result.verdict, (Verdict.REFUSED, Verdict.RESET))

    def test_total_loss_is_reported_as_filtered(self) -> None:
        # The gap this file exists to close: a dropped SYN must become FILTERED, not
        # CLOSED and not UNDETERMINED, and it must not be mistaken for an open port.
        _add_loss(100.0)
        result = self._probe(port=9, base_timeout_s=0.5)
        self.assertIs(
            result.state,
            PortState.FILTERED,
            f"100% loss produced {result.state.value} ({result.verdict.value}); a dropped "
            "SYN must be indistinguishable from a firewall, which is what FILTERED means",
        )
        self.assertIs(result.verdict, Verdict.TIMEOUT)

    def test_partial_loss_does_not_change_the_verdict(self) -> None:
        # With loss below 100% a retransmitted SYN can still arrive, so the connect may
        # succeed or be refused - but it must never be reported as open, and never crash.
        _add_loss(50.0)
        result = self._probe(port=9, base_timeout_s=0.8)
        self.assertIsNot(result.state, PortState.OPEN)

    def test_delay_is_measured_rather_than_mistaken_for_absence(self) -> None:
        # A 300 ms round trip against a 0.05 s timeout must time out; the same port with a
        # generous timeout must be refused. That is the difference between "slow" and
        # "absent", and it is what the RTT estimator exists to get right.
        _add_delay(300)
        tight = self._probe(port=9, base_timeout_s=0.05, min_timeout_s=0.05, max_timeout_s=0.05)
        generous = self._probe(port=9, base_timeout_s=2.0, min_timeout_s=2.0, max_timeout_s=2.0)
        self.assertIs(
            tight.state,
            PortState.FILTERED,
            "a 300 ms path against a 50 ms timeout should be inconclusive",
        )
        self.assertIs(
            generous.state,
            PortState.CLOSED,
            "the same path with a generous timeout should resolve to a refusal",
        )

    # ------------------------------------------------------------------ helpers

    def _probe(
        self,
        *,
        port: int,
        base_timeout_s: float = 1.0,
        min_timeout_s: float = 0.2,
        max_timeout_s: float = 2.0,
    ) -> ProbeResult:
        tmp = Path(tempfile.mkdtemp(prefix="schedprobe-netem-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        config = ScanConfig(
            targets=(PEER_ADDRESS,),
            ports=(port,),
            backend="real",
            planner=PlannerConfig(kind="fixed", seed=1, cost_budget=100_000),
            network=NetworkConfig(
                concurrency=1,
                base_timeout_s=base_timeout_s,
                min_timeout_s=min_timeout_s,
                max_timeout_s=max_timeout_s,
                max_hosts=4,
                max_ports=4,
            ),
        ).validate()
        backend = RealTcpBackend(config=config, allow=[PEER_ADDRESS])
        engine = ScanEngine(config, backend=backend, out_dir=str(tmp), run_id="netem")
        run = asyncio.run(engine.run())
        self.assertEqual(
            run.manifest["probe_errors"],
            [],
            "the engine recorded probe errors, so the classification below is about a "
            "broken run rather than about the network condition",
        )
        return run.results[(PEER_ADDRESS, port)]


def _setup_topology() -> None:
    _require("ip")
    _require("tc")
    _teardown()
    _run("ip", "netns", "add", NAMESPACE)
    _run("ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_PEER)
    _run("ip", "link", "set", VETH_PEER, "netns", NAMESPACE)
    _run("ip", "addr", "add", f"{HOST_ADDRESS}/24", "dev", VETH_HOST)
    _run("ip", "link", "set", VETH_HOST, "up")
    _run("ip", "netns", "exec", NAMESPACE, "ip", "addr", "add", f"{PEER_ADDRESS}/24", "dev", VETH_PEER)
    _run("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", VETH_PEER, "up")
    _run("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", "lo", "up")
    # Prove the path is actually usable before any test runs, so a broken topology shows
    # up as a skip here rather than as a mysterious classification failure later.
    probe = _run("ping", "-c", "1", "-W", "2", PEER_ADDRESS, check=False)
    if probe.returncode != 0:
        raise _SetupError(
            f"the veth pair does not pass traffic: {(probe.stderr or probe.stdout).strip()[:160]}"
        )


def _clear_qdisc() -> None:
    _run("tc", "qdisc", "del", "dev", VETH_HOST, "root", check=False)


def _add_loss(percent: float) -> None:
    _run("tc", "qdisc", "add", "dev", VETH_HOST, "root", "netem", "loss", f"{percent}%")


def _add_delay(milliseconds: int) -> None:
    _run("tc", "qdisc", "add", "dev", VETH_HOST, "root", "netem", "delay", f"{milliseconds}ms")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
