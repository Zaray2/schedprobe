"""Injected packet loss, because loopback cannot produce it on its own.

This is the gap a reviewer named before I did: everything in the suite ran either against
the simulator or against loopback, and a TCP connect yields `FILTERED` only when packets
are *dropped* rather than answered. So the timeout path, the RTT estimator and the
confirmation logic - the whole inconclusive-result branch - had no real-socket coverage at
all on the authoring host.

They also rejected the excuse I gave for that: "needs a non-loopback host I own" describes
a priority problem as a resource problem. They were right, so this file injects the loss
locally instead of waiting for a host.

**Two mechanisms, tried in order.**

`netns`
    A network namespace with a veth pair on 10.200.1.0/24 driven by `tc netem`. This is
    the cleaner experiment: it gives real loss, real delay, and a refusal that travels a
    real path.

`iptables`
    A DROP rule on a loopback port. It produces the one thing the classification path
    actually needs - a SYN that is silently dropped instead of answered - with far fewer
    environment requirements. It cannot inject delay, so the delay test is namespace-only.

The fallback exists because the first CI run with the namespace version *skipped on a
GitHub-hosted runner*, and the only reason I know that is that the run went red: the
workflow fails when these tests skip, rather than reporting a green build that covered
nothing. Guessing which mechanism a runner supports is how the previous attempt produced a
green build that meant nothing.

**Failure policy.** If neither mechanism works the tests skip with the measured reason -
the command, its exit code and its output - and the CI step that runs them fails. An
assertion failure after a working setup fails loudly, because that is a real disagreement
about the code.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
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
VETH_HOST = "schedprobe-veth0"
VETH_PEER = "schedprobe-veth1"
HOST_ADDRESS = "10.200.1.1"
PEER_ADDRESS = "10.200.1.2"
NETNS_PORT = 9


class _SetupError(RuntimeError):
    """Carries the failing command and its output, so a skip can explain itself."""


def _as_root() -> list[str]:
    """Prefix for commands needing root, or nothing when already root."""
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        return ["sudo", "-n"]
    return []


def _run(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run([*_as_root(), *argv], capture_output=True, text=True, check=False, timeout=30)
    except OSError as exc:
        raise _SetupError(f"{argv[0]!r} could not be executed: {exc}") from exc
    if check and proc.returncode != 0:
        raise _SetupError(
            f"{' '.join(argv)!r} exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:200]}"
        )
    return proc


def _require(command: str) -> None:
    if shutil.which(command) is None:
        raise _SetupError(f"the {command!r} command is not available on this host")


def _teardown() -> None:
    """Best-effort cleanup. Never raises, because it runs from a finally block."""
    for argv in (("ip", "netns", "del", NAMESPACE), ("ip", "link", "del", VETH_HOST)):
        try:
            subprocess.run([*_as_root(), *argv], capture_output=True, text=True, check=False, timeout=30)
        except OSError:
            return


def _setup_netns() -> None:
    _require("ip")
    _require("tc")
    _teardown()
    _run("ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_PEER)
    _run("ip", "netns", "add", NAMESPACE)
    _run("ip", "link", "set", VETH_PEER, "netns", NAMESPACE)
    _run("ip", "addr", "add", f"{HOST_ADDRESS}/24", "dev", VETH_HOST)
    _run("ip", "link", "set", VETH_HOST, "up")
    _run(
        "ip",
        "netns",
        "exec",
        NAMESPACE,
        "ip",
        "addr",
        "add",
        f"{PEER_ADDRESS}/24",
        "dev",
        VETH_PEER,
    )
    _run("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", VETH_PEER, "up")
    _run("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", "lo", "up")
    if (
        shutil.which("ping")
        and _run("ping", "-c", "1", "-W", "2", PEER_ADDRESS, check=False).returncode != 0
    ):
        raise _SetupError("the veth pair does not pass traffic")


class _Mechanism:
    """Which injection method is in force, decided by trying them rather than by guessing."""

    netns = "netns"
    iptables = "iptables"
    used: str | None = None
    port: int = NETNS_PORT

    @classmethod
    def host(cls) -> str:
        return PEER_ADDRESS if cls.used == cls.netns else "127.0.0.1"

    @classmethod
    def _loopback_drop_works(cls) -> bool:
        """Verify an iptables DROP rule really turns a loopback connect into a timeout."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind(("127.0.0.1", 0))
            port = holder.getsockname()[1]
        _run("iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP", check=False)
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.6)
            try:
                probe.connect(("127.0.0.1", port))
                return False
            except TimeoutError:
                return True
            except OSError:
                return False
            finally:
                probe.close()
        finally:
            _run(
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
                check=False,
            )

    @classmethod
    def setup(cls) -> str:
        if os.name == "nt":
            raise _SetupError("no packet injection is available on Windows")
        try:
            _setup_netns()
        except _SetupError as namespace_error:
            _teardown()
            if shutil.which("iptables") is None:
                raise _SetupError(
                    f"network namespace unavailable ({namespace_error}), and iptables is absent"
                ) from namespace_error
            if not cls._loopback_drop_works():
                raise _SetupError(
                    f"network namespace unavailable ({namespace_error}), and an iptables "
                    "DROP rule on a loopback port did not produce a timeout either"
                ) from namespace_error
            cls.used = cls.iptables
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
                holder.bind(("127.0.0.1", 0))
                cls.port = holder.getsockname()[1]
            return cls.iptables
        cls.used = cls.netns
        cls.port = NETNS_PORT
        return cls.netns

    @classmethod
    def clear(cls) -> None:
        if cls.used == cls.netns:
            _run("tc", "qdisc", "del", "dev", VETH_HOST, "root", check=False)
        elif cls.used == cls.iptables:
            _run(
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                str(cls.port),
                "-j",
                "DROP",
                check=False,
            )

    @classmethod
    def drop_all(cls) -> None:
        if cls.used == cls.netns:
            _run("tc", "qdisc", "add", "dev", VETH_HOST, "root", "netem", "loss", "100%")
        else:
            _run("iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(cls.port), "-j", "DROP")

    @classmethod
    def drop_half(cls) -> None:
        if cls.used == cls.netns:
            _run("tc", "qdisc", "add", "dev", VETH_HOST, "root", "netem", "loss", "50%")
        else:
            # iptables has no probabilistic drop without the statistic module, and a
            # partial case adds little over the total case, so it is skipped explicitly
            # rather than quietly redefined as something else.
            raise _SetupError("partial loss needs the netns mechanism")

    @classmethod
    def delay(cls, milliseconds: int) -> None:
        if cls.used != cls.netns:
            raise _SetupError("delay injection needs the netns mechanism")
        _run("tc", "qdisc", "add", "dev", VETH_HOST, "root", "netem", "delay", f"{milliseconds}ms")


@tier(TIER_ORACLE)
class TestInjectedNetworkConditions(unittest.TestCase):
    """Real dropped packets on a real path, by whichever mechanism the host supports."""

    reason: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.reason = None
        # The netns mechanism needs a second namespace; the iptables one needs a listener
        # in the peer position only for the delay test, so nothing is started here.
        cls._hold: socket.socket | None = None
        try:
            _Mechanism.setup()
        except _SetupError as exc:
            cls.reason = str(exc)
            _teardown()
        except Exception as exc:  # pragma: no cover - unexpected environment shape
            cls.reason = f"{exc.__class__.__name__}: {exc}"
            _teardown()

    @classmethod
    def tearDownClass(cls) -> None:
        _Mechanism.clear()
        _teardown()

    def setUp(self) -> None:
        if self.reason:
            self.skipTest(self.reason)
        _Mechanism.clear()

    def tearDown(self) -> None:
        if not self.reason:
            _Mechanism.clear()

    def test_a_dropped_syn_becomes_filtered_not_closed(self) -> None:
        # The gap this file exists to close. A dropped SYN must become FILTERED - not
        # CLOSED (which would mean the stack answered and refused) and not OPEN.
        _Mechanism.drop_all()
        result = self._probe(base_timeout_s=0.5)
        self.assertIs(
            result.state,
            PortState.FILTERED,
            f"a dropped SYN produced {result.state.value} ({result.verdict.value}) via the "
            f"{_Mechanism.used} mechanism; it must be indistinguishable from a firewall",
        )
        self.assertIs(result.verdict, Verdict.TIMEOUT)

    def test_the_same_target_is_not_filtered_without_the_rule(self) -> None:
        # The control, and the reason the test above is meaningful: with the injection
        # removed, the identical probe must *not* report FILTERED. Without this, a probe
        # that always times out for some unrelated reason would pass the test above.
        result = self._probe(base_timeout_s=1.0)
        self.assertIsNot(
            result.state,
            PortState.FILTERED,
            "the target is inconclusive even with no injected loss, so the loss test above "
            "proves nothing; the mechanism is not the cause of the timeout",
        )

    def test_slow_is_not_the_same_as_absent(self) -> None:
        # A 300 ms path against a 50 ms timeout is inconclusive; the same path with a
        # generous timeout resolves. That distinction is what the RTT estimator is for,
        # and it can only be tested where delay can be injected.
        if _Mechanism.used != _Mechanism.netns:
            self.skipTest(f"delay injection is unavailable via the {_Mechanism.used} mechanism")
        _Mechanism.delay(300)
        tight = self._probe(base_timeout_s=0.05, min_timeout_s=0.05, max_timeout_s=0.05)
        generous = self._probe(base_timeout_s=2.0, min_timeout_s=2.0, max_timeout_s=2.0)
        self.assertIs(tight.state, PortState.FILTERED, "50 ms is not enough for a 300 ms path")
        self.assertIsNot(
            generous.state,
            PortState.FILTERED,
            "2 s is ample for a 300 ms path, so it must resolve rather than time out",
        )

    def test_the_mechanism_in_use_is_reported(self) -> None:
        # A test that cannot say how it injected loss cannot be trusted to have done it.
        self.assertIn(_Mechanism.used, (_Mechanism.netns, _Mechanism.iptables))

    # ------------------------------------------------------------------ helper

    def _probe(
        self,
        *,
        base_timeout_s: float = 1.0,
        min_timeout_s: float = 0.2,
        max_timeout_s: float = 2.0,
    ) -> ProbeResult:
        host = _Mechanism.host()
        tmp = Path(tempfile.mkdtemp(prefix="schedprobe-netem-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        config = ScanConfig(
            targets=(host,),
            ports=(_Mechanism.port,),
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
        backend = RealTcpBackend(config=config, allow=[host])
        engine = ScanEngine(config, backend=backend, out_dir=str(tmp), run_id="netem")
        run = asyncio.run(engine.run())
        self.assertEqual(
            run.manifest["probe_errors"],
            [],
            "the engine recorded probe errors, so the classification is about a broken run "
            "rather than about the injected condition",
        )
        return run.results[(host, _Mechanism.port)]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
