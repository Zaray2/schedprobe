"""Report whether this host can inject packet loss, and with which mechanism.

The CI step that runs ``tests/test_netem.py`` has to distinguish two situations that look
identical in a test log:

* the host cannot drop packets at all, so the test skipped for environment reasons; and
* the host can, but something in the code or the setup is wrong, so it skipped anyway.

The first is not a build failure - it is a fact about the runner, and it should be visible
rather than fatal. The second absolutely is a failure. This script answers which one
applies, so the workflow can act on the answer instead of guessing.

It was written after two consecutive red builds. The first enforcement failed the build
whenever the tests skipped, which was correct in principle and wrong in practice: this
runner has neither the network-namespace privileges nor a working iptables DROP, so the
build went red twice for a reason no code change could fix. A permanently red build trains
people to ignore red, which costs more than the gap it was guarding.

    python scripts/netem_probe.py
    # exit 0 = a mechanism works here, or none does (with the reason printed)
    # exit 1 = nothing to report; used only for an internal error
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.test_netem import _Mechanism, _SetupError, _teardown  # noqa: E402


def main() -> int:
    try:
        used = _Mechanism.setup()
    except _SetupError as exc:
        print("unavailable: no packet-injection mechanism works on this host")
        print(f"reason: {exc}")
        # Emitted as a GitHub annotation so it shows up on the run, not only in the log.
        print(
            "::warning title=injected-loss tests cannot run here::"
            f"{exc} - the FILTERED path is exercised by the simulator only in this build"
        )
        _teardown()
        return 0
    print(f"available: the tests will use the {used} mechanism")
    _teardown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
