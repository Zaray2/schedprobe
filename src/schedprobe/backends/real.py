"""Real TCP connect backend (asyncio, standard library only).

Properties that matter for the rest of the project:

* **No external process, no privileges.** ``asyncio.open_connection`` needs no
  raw sockets, so the tool runs unprivileged on Windows/Linux/macOS and cannot be
  repurposed as a packet injector.
* **Cost is wall-clock milliseconds.** The unit string is recorded in the manifest
  so nobody compares a simulated run with a real one by accident.
* **Every outcome is reported, none is invented.** A timeout is a timeout: the
  result carries ``Verdict.TIMEOUT`` and a confidence below the confirmation
  threshold, and the planner decides what to do about it.
* **Banners are opt-in and bounded.** With ``grab_banner`` enabled, the backend
  performs one *read-only* fetch (no payload is ever sent) with a hard byte cap and
  a short deadline, and records only a printable-truncated preview. Nothing is
  written to disk unless the operator chose the format that includes it.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import time
from collections.abc import Iterable
from contextlib import suppress
from typing import Any

from ..errors import BackendError
from ..models import PortState, ProbeResult, Verdict
from .base import ProbeRequest, RateLimiter, ScopedProbeBackend, confidence_for, merge_stats

__all__ = ["RealTcpBackend"]

_BANNER_BYTE_CAP = 128
_BANNER_PREVIEW_LEN = 64
_PRINTABLE = set(range(0x20, 0x7F))


def _sanitize_banner(raw: bytes) -> str:
    """Render an untrusted banner as a short, printable, control-character-free string.

    Remote data is attacker-controlled; it must never reach a log file or a
    terminal with embedded escapes intact.
    """
    text = "".join(chr(byte) if byte in _PRINTABLE else "." for byte in raw[:_BANNER_BYTE_CAP])
    return text[:_BANNER_PREVIEW_LEN]


class RealTcpBackend(ScopedProbeBackend):
    """Performs real TCP connect probes against validated targets."""

    name = "real"
    cost_unit = "ms"

    def __init__(
        self,
        *,
        config: Any,
        allow: Iterable[str] | None = None,
        grab_banner: bool = False,
        rate_limit_pps: float | None = None,
    ) -> None:
        super().__init__(allow=set(allow) if allow is not None else None)
        if config is None:
            raise BackendError("real backend requires a ScanConfig")
        self.config = config
        self.grab_banner = bool(grab_banner)
        network = getattr(config, "network", None)
        rate = rate_limit_pps if rate_limit_pps is not None else getattr(network, "rate_limit_pps", 0.0)
        self.limiter = RateLimiter(rate=float(rate or 0.0))
        self.resolve_timeout = float(getattr(network, "resolve_timeout_s", 2.0))
        self._dns_cache: dict[str, str] = {}
        self._dns_lock = asyncio.Lock()

    # ------------------------------------------------------------------ probing
    async def probe(self, request: ProbeRequest) -> ProbeResult:
        self._assert_scoped(request.host)
        await self.limiter.acquire()
        started = time.monotonic()
        state, verdict, detail = await self._connect(request)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        cost = max(1, elapsed_ms)
        if state is PortState.OPEN and self.grab_banner:
            banner = await self._read_banner(request)
            if banner:
                detail = f"banner={banner}"
        result = ProbeResult(
            host=request.host,
            port=request.port,
            state=state,
            verdict=verdict,
            cost_units=cost,
            confidence=confidence_for(verdict, request.attempt),
            attempt=request.attempt,
            detail=detail,
        )
        merge_stats(self._stats, result)
        return result

    async def _connect(self, request: ProbeRequest) -> tuple[PortState, Verdict, str]:
        timeout = request.effective_timeout_s
        target = request.host
        try:
            resolved = await self._resolve(target)
        except _ResolutionError as exc:
            return PortState.UNDETERMINED, Verdict.UNRESOLVED, f"dns: {exc.reason}"
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host=resolved, port=request.port), timeout=timeout
            )
            return PortState.OPEN, Verdict.CONNECTED, "tcp handshake completed"
        except TimeoutError:
            return PortState.FILTERED, Verdict.TIMEOUT, f"no response within {timeout:.3f}s"
        except ConnectionRefusedError:
            return PortState.CLOSED, Verdict.REFUSED, "connection refused"
        except ConnectionResetError:
            return PortState.CLOSED, Verdict.RESET, "connection reset during handshake"
        except OSError as exc:
            return self._classify_oserror(exc, timeout)
        finally:
            if writer is not None:
                with suppress(OSError):
                    writer.close()

    def _classify_oserror(self, exc: OSError, timeout: float) -> tuple[PortState, Verdict, str]:
        """Map OS errors without guessing.

        Windows surfaces refused connections as ``WSAECONNREFUSED`` (10061) and
        unreachable hosts as 10065/10051; POSIX uses ``ECONNREFUSED``/``EHOSTUNREACH``.
        Anything we cannot classify becomes ``UNDETERMINED`` rather than a
        confident wrong answer.
        """
        err = getattr(exc, "errno", None)
        winerr = getattr(exc, "winerror", None)
        if err == errno.ECONNREFUSED or winerr == 10061:
            return PortState.CLOSED, Verdict.REFUSED, "connection refused"
        if err == errno.ECONNRESET or winerr in (10054, 10053):
            return PortState.CLOSED, Verdict.RESET, "connection reset"
        if err in (errno.EHOSTUNREACH, errno.ENETUNREACH) or winerr in (10065, 10051, 10050):
            return PortState.UNDETERMINED, Verdict.HOST_UNREACHABLE, "host or network unreachable"
        if err == errno.ETIMEDOUT or winerr == 10060:
            return PortState.FILTERED, Verdict.TIMEOUT, "connection timed out"
        return PortState.UNDETERMINED, Verdict.ERROR, f"os error: {exc.__class__.__name__}"

    # --------------------------------------------------------------------- dns
    async def _resolve(self, host: str) -> str:
        """Resolve a hostname once per run, with a bounded timeout.

        IP literals short-circuit. The cache is per-backend-instance and never
        persisted, so no target list leaks into a cache file.
        """
        try:
            socket.inet_pton(socket.AF_INET, host)
            return host
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host.split("%", maxsplit=1)[0])
            return host
        except OSError:
            pass
        async with self._dns_lock:
            cached = self._dns_cache.get(host)
            if cached is not None:
                return cached
            loop = asyncio.get_running_loop()
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=self.resolve_timeout
                )
            except TimeoutError as exc:
                raise _ResolutionError("timed out") from exc
            except socket.gaierror as exc:
                raise _ResolutionError(f"{exc.__class__.__name__}") from exc
            if not infos:
                raise _ResolutionError("no addresses")
            # sockaddr[0] is the address text for both AF_INET and AF_INET6.
            resolved = str(infos[0][4][0])
            self._dns_cache[host] = resolved
            return resolved

    # ------------------------------------------------------------------ banners
    async def _read_banner(self, request: ProbeRequest) -> str:
        """Read-only banner fetch: never sends a byte, never blocks the schedule."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=request.host, port=request.port),
                timeout=min(request.effective_timeout_s, 1.0),
            )
        except (TimeoutError, OSError):
            return ""
        try:
            raw = await asyncio.wait_for(reader.read(_BANNER_BYTE_CAP), timeout=0.4)
        except (TimeoutError, OSError):
            raw = b""
        finally:
            with suppress(OSError):
                writer.close()
        return _sanitize_banner(raw)

    def describe(self) -> dict[str, Any]:
        return {
            "backend": self.name,
            "cost_unit": self.cost_unit,
            "grab_banner": self.grab_banner,
            "rate_limit_pps": self.limiter.rate,
            "resolve_timeout_s": self.resolve_timeout,
        }


class _ResolutionError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
