"""Target and port parsing plus scope validation.

This module is the only place that turns untrusted user input into a target set.
It is intentionally paranoid: no target string ever reaches a backend before it
has passed :func:`validate_targets`, and hostnames are matched against an
RFC 1123 character set so that shell metacharacters cannot survive parsing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Sequence

from .errors import TargetValidationError
from .models import normalize_target, segment_of

__all__ = [
    "COMMON_PORTS",
    "parse_ports",
    "expand_targets",
    "validate_targets",
    "segment_map",
    "SHELL_METACHARS",
]

COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    631, 993, 995, 1025, 1080, 1433, 1521, 1723, 2049, 2181, 3000, 3306, 3389,
    4443, 5000, 5432, 5601, 5900, 5984, 6379, 7001, 8000, 8008, 8080, 8081, 8443,
    8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
)

SHELL_METACHARS: frozenset[str] = frozenset("&|;`$<>()[]{}*?!'\"\\\n\r\t #")

# RFC 1123 host label: a-z A-Z 0-9, hyphen inside, dot separated.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_PORT_TOKEN_RE = re.compile(r"^(?P<a>\d{1,5})(?:-(?P<b>\d{1,5}))?$")

MAX_CIDR_ADDRESSES = 1 << 16  # refuse to expand anything bigger; guard, not a limit to brag about


def _reject(text: str) -> None:
    bad = sorted({ch for ch in text if ch in SHELL_METACHARS})
    if bad:
        raise TargetValidationError(
            "target contains characters that are never valid in a host spec",
            value=text[:64],
            offending="".join(bad),
        )


def expand_targets(raw_targets: Iterable[str], max_hosts: int = 4096) -> tuple[str, ...]:
    """Expand a mixed list of literals, CIDRs and hostnames into concrete hosts.

    Behaviour:
      * plain IP literal -> itself
      * ``a.b.c.d/len`` -> every usable host address in the network
        (network/broadcast addresses are dropped for IPv4 prefixes <= /30)
      * hostname -> itself (no DNS resolution here; resolution is a backend concern)
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_targets:
        if not isinstance(raw, str) or not raw.strip():
            raise TargetValidationError("empty or non-string target", value=repr(raw)[:64])
        text = raw.strip()
        _reject(text)
        if "/" in text:
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError as exc:
                raise TargetValidationError(f"invalid CIDR {text!r}: {exc}") from exc
            if network.num_addresses > MAX_CIDR_ADDRESSES:
                raise TargetValidationError(
                    "CIDR is too large to expand safely",
                    value=text,
                    addresses=network.num_addresses,
                    limit=MAX_CIDR_ADDRESSES,
                )
            hosts = list(network.hosts()) if network.version == 4 and network.prefixlen <= 30 \
                else list(network)
            for host in hosts:
                text_host = str(host)
                if text_host not in seen:
                    seen.add(text_host)
                    out.append(text_host)
                if len(out) > max_hosts:
                    raise TargetValidationError(
                        "target expansion exceeds max_hosts",
                        limit=max_hosts,
                        value=raw,
                    )
            continue
        try:
            normalized = normalize_target(text)
        except ValueError as exc:
            raise TargetValidationError(f"invalid target {text!r}: {exc}") from exc
        if _HOSTNAME_RE.match(normalized) or normalized.replace(".", "").replace(":", "").isalnum():
            pass
        else:
            raise TargetValidationError("host is neither a valid IP literal nor a valid hostname",
                                        value=text[:64])
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    if not out:
        raise TargetValidationError("target set is empty after expansion")
    return tuple(out)


def parse_ports(spec: str | Sequence[int] | None, *, common: Sequence[int] = COMMON_PORTS) -> tuple[int, ...]:
    """Parse ``80,443,8000-8100`` style port specs, or a preset name.

    Presets: ``top50`` (see :data:`COMMON_PORTS`), ``all`` (1-65535).
    """
    if spec is None:
        return tuple(common)
    if isinstance(spec, (list, tuple, set, frozenset)):
        tokens = [str(item) for item in spec]
    else:
        text = str(spec).strip()
        if not text:
            raise TargetValidationError("empty port specification")
        preset = text.lower()
        if preset in {"top50", "common", "top"}:
            return tuple(common)
        if preset == "all":
            return tuple(range(1, 65536))
        tokens = [part.strip() for part in text.split(",") if part.strip()]

    ports: list[int] = []
    seen: set[int] = set()
    for token in tokens:
        match = _PORT_TOKEN_RE.match(token)
        if not match:
            raise TargetValidationError("invalid port token", value=token[:32])
        start = int(match.group("a"))
        end = int(match.group("b")) if match.group("b") else start
        if start > end:
            raise TargetValidationError("port range is reversed", value=token[:32])
        if not 1 <= start <= 65535 or not 1 <= end <= 65535:
            raise TargetValidationError("port out of range 1-65535", value=token[:32])
        for port in range(start, end + 1):
            if port not in seen:
                seen.add(port)
                ports.append(port)
        if len(ports) > 65535:
            raise TargetValidationError("port specification expands beyond 65535 entries")
    if not ports:
        raise TargetValidationError("port specification is empty")
    return tuple(ports)


def validate_targets(targets: Sequence[str], safety, max_hosts: int = 4096) -> tuple[str, ...]:
    """Enforce the scope guard described in ``SafetyConfig``.

    Every target must be explicitly permitted by the caller's safety section:
    by default loopback and private space are allowed and public space is not.
    The error message always names the flag that would allow it, so a user in a
    hurry can fix the problem without reading source code.
    """
    if not targets:
        raise TargetValidationError("no targets supplied")
    checked: list[str] = []
    for target in targets:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            if not safety.allow_dns:
                raise TargetValidationError(
                    "hostname targets are disabled by safety.allow_dns", value=target[:64]
                )
            if not _HOSTNAME_RE.match(target):
                raise TargetValidationError(
                    "hostname does not look like an RFC 1123 name", value=target[:64]
                )
            checked.append(target)
            continue
        # Order matters here, and it is not arbitrary:
        #   1. loopback first, because ``::1`` is also flagged ``is_reserved``;
        #   2. unspecified/multicast next, because ``0.0.0.0`` is flagged ``is_private``
        #      and would otherwise be admitted through the private door;
        #   3. private/link-local;
        #   4. everything else is public and needs an explicit opt-in.
        if addr.is_loopback:
            if not safety.allow_loopback:
                raise TargetValidationError(
                    "loopback target refused by safety.allow_loopback", value=target
                )
        elif addr.is_unspecified or addr.is_multicast or addr.is_reserved:
            raise TargetValidationError(
                "reserved/multicast/unspecified target refused", value=target
            )
        elif addr.is_private or addr.is_link_local:
            if not safety.allow_private:
                raise TargetValidationError(
                    "private target refused by safety.allow_private", value=target
                )
        else:
            if not safety.allow_public:
                raise TargetValidationError(
                    "public target refused; pass --allow-public only for assets you are "
                    "authorized to test",
                    value=target,
                )
        checked.append(target)
    if len(checked) > max_hosts:
        raise TargetValidationError("too many targets", count=len(checked), limit=max_hosts)
    return tuple(checked)


def segment_map(hosts: Iterable[str], prefix_len: int = 24) -> dict[str, tuple[str, ...]]:
    """Group hosts by segment, preserving deterministic ordering."""
    grouped: dict[str, list[str]] = {}
    for host in hosts:
        grouped.setdefault(segment_of(host, prefix_len), []).append(host)
    return {key: tuple(sorted(values)) for key, values in sorted(grouped.items())}
