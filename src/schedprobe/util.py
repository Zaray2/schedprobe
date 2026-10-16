"""Small, dependency-free helpers: deterministic hashing and structured logging.

Two rules this module enforces:

* **Determinism**: anything that needs randomness takes an explicit ``random.Random``
  created from a recorded seed. There is no module-level RNG anywhere in the
  package, so a run cannot be perturbed by import order.
* **Log hygiene**: :func:`redact` and :class:`SecretFilter` exist so that host
  identifiers and environment-derived values can be scrubbed before they reach a
  log file. Tests assert on both.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import re
import sys
from typing import Any, Mapping

__all__ = [
    "canonical_json",
    "sha256_hex",
    "hash_pair",
    "derive_rng",
    "seed_bytes",
    "redact",
    "SecretFilter",
    "configure_logging",
    "get_logger",
    "format_hhmmss",
    "clamp",
]

_HASH_PREFIX = "sha256:"


def canonical_json(payload: Mapping[str, Any]) -> str:
    """Serialize a mapping to canonical JSON (sorted keys, no spaces, ASCII safe).

    Used both for hashing evidence records and for writing them, so the bytes on
    disk are exactly the bytes that were hashed. If these ever diverged, the
    evidence chain would be unverifiable - which is why the writer never uses a
    second serializer.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def seed_bytes(seed: int | str, salt: str = "") -> bytes:
    """Turn a user-facing seed into 32 bytes deterministically."""
    material = f"{seed}|{salt}".encode("utf-8")
    return hashlib.sha256(material).digest()


def derive_rng(seed: int | str, salt: str) -> random.Random:
    """Create an independent, reproducible RNG stream for ``salt``."""
    return random.Random(seed_bytes(seed, salt))


def hash_pair(host: str, port: int, salt: str = "") -> str:
    """Stable short digest of a (host, port) pair, optionally keyed by ``salt``.

    With a per-run salt this is a pseudonym: consistent within one evidence log,
    not correlatable across runs. Used by ``--redact``.
    """
    key = salt.encode("utf-8")
    digest = hmac.new(key, f"{host}:{port}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"h:{digest[:12]}"


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd)\b\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def redact(text: str, *, salt: str = "", hide_ips: bool = True) -> str:
    """Scrub IP literals and credential-looking substrings from free text.

    This is a defence-in-depth measure for log lines and error messages. It is
    *not* a replacement for not logging secrets in the first place.
    """
    out = text
    for pattern in _SECRET_PATTERNS:
        # Replace the whole match, never keep any part of the secret.
        out = pattern.sub("<redacted>", out)
    if hide_ips:
        out = _IPV4_RE.sub(lambda m: f"h:{sha256_hex((salt or 'nosalt') + ':' + m.group(0))[:12]}", out)
    return out


class SecretFilter(logging.Filter):
    """Logging filter that applies :func:`redact` to every rendered message."""

    def __init__(self, salt: str = "", hide_ips: bool = True) -> None:
        super().__init__()
        self._salt = salt
        self._hide_ips = hide_ips

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - stdlib API
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - defensive, never swallow silently
            rendered = str(record.msg)
        record.msg = redact(rendered, salt=self._salt, hide_ips=self._hide_ips)
        record.args = ()
        return True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def configure_logging(
    level: str = "INFO",
    *,
    stream: Any | None = None,
    hide_ips: bool = False,
    salt: str = "",
) -> logging.Logger:
    """Attach a single stderr handler with a stable, greppable format.

    ``hide_ips`` defaults to False so normal operation is readable; the CLI turns
    it on when ``--redact`` is requested.
    """
    logger = logging.getLogger("schedprobe")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(
        logging.Formatter(fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    )
    handler.addFilter(SecretFilter(salt=salt, hide_ips=hide_ips))
    logger.addHandler(handler)
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        numeric = logging.INFO
    logger.setLevel(numeric)
    logger.propagate = False
    return logger


def format_hhmmss(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    hours, rem = divmod(int(seconds), 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:d}h{minutes:02d}m{secs:02d}s"
    return f"{minutes:d}m{secs:02d}s"


def clamp(value: float, low: float, high: float) -> float:
    if low > high:
        raise ValueError(f"invalid clamp range: low={low} > high={high}")
    return max(low, min(high, value))
