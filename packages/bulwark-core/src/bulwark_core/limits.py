"""Resource limits that keep the scanner safe against hostile input.

Airlock ingests untrusted archives and pickle streams. Without bounds, a zip
bomb or a pickle crafted to explode ``genops`` could hang or OOM the scanner —
turning a defensive tool into a denial-of-service vector. These limits cap what
any single artifact can cost. Defaults are generous for real models but fatal to
bombs; override via ``AIRLOCK_LIMIT_*`` environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_MiB = 1024 * 1024
_GiB = 1024 * _MiB


def read_bounded(path: Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes from ``path``.

    A scanner ingests hostile files; ``path.read_bytes()`` on a crafted multi-GB
    artifact would OOM the process. Use this anywhere the whole file would otherwise
    be slurped — content beyond ``limit`` cannot change a magic-byte or header-level
    verdict.
    """
    with path.open("rb") as fh:
        return fh.read(limit)


@dataclass(frozen=True)
class Limits:
    """Hard caps applied during static inspection."""

    max_pickle_opcodes: int = 2_000_000  # stop disassembly after this many opcodes
    max_archive_members: int = 20_000  # stop enumerating archive members
    max_uncompressed_bytes: int = 4 * _GiB  # total declared uncompressed archive size
    max_compression_ratio: float = 100.0  # uncompressed/compressed → bomb signal
    max_member_bytes: int = 512 * _MiB  # per-member bytes we will actually parse
    max_nested_blob_bytes: int = 8 * _MiB  # cap on a decoded nested (base64) payload
    max_strings: int = 200  # embedded strings retained per stream
    max_string_len: int = 400  # per-string truncation
    max_files: int = 100_000  # files enumerated when walking a target directory
    connect_timeout_s: float = 20.0  # per-connection budget for a live MCP scan


def walk_files(root: Path, limits: Limits | None = None) -> list[Path]:
    """Enumerate files under ``root``, bounded and without escaping via symlinks.

    ``Path.rglob`` follows symbolic links, so a hostile artifact directory containing
    a link to ``/`` would make a scan traverse the entire filesystem — a
    denial-of-service in a tool that otherwise bounds every parse. Two controls:

    - **containment** — each entry is resolved and must remain under the resolved
      root, which rejects escaping symlinks the same way the rule feed rejects
      zip-slip (``..`` *and* absolute/drive paths);
    - **a file cap** — ``max_files``, overridable via ``AIRLOCK_LIMIT_MAX_FILES``.

    Results are sorted for deterministic, reproducible output across machines.
    """
    lim = limits or DEFAULT_LIMITS
    try:
        root_resolved = root.resolve()
    except OSError:
        return []

    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(out) >= lim.max_files:
            break
        try:
            if not path.is_file():
                continue
            if not path.resolve().is_relative_to(root_resolved):
                continue  # symlink escaping the scan root — skip
        except OSError:  # broken link, permission error, path too long
            continue
        out.append(path)
    return out


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def from_env() -> Limits:
    """Build limits, applying any ``AIRLOCK_LIMIT_*`` overrides."""
    base = Limits()
    return Limits(
        max_pickle_opcodes=_env_int("AIRLOCK_LIMIT_PICKLE_OPCODES", base.max_pickle_opcodes),
        max_archive_members=_env_int("AIRLOCK_LIMIT_ARCHIVE_MEMBERS", base.max_archive_members),
        max_uncompressed_bytes=_env_int(
            "AIRLOCK_LIMIT_UNCOMPRESSED_BYTES", base.max_uncompressed_bytes
        ),
        max_compression_ratio=_env_float(
            "AIRLOCK_LIMIT_COMPRESSION_RATIO", base.max_compression_ratio
        ),
        max_member_bytes=_env_int("AIRLOCK_LIMIT_MEMBER_BYTES", base.max_member_bytes),
        max_nested_blob_bytes=_env_int(
            "AIRLOCK_LIMIT_NESTED_BLOB_BYTES", base.max_nested_blob_bytes
        ),
        max_strings=_env_int("AIRLOCK_LIMIT_STRINGS", base.max_strings),
        max_string_len=_env_int("AIRLOCK_LIMIT_STRING_LEN", base.max_string_len),
        max_files=_env_int("AIRLOCK_LIMIT_MAX_FILES", base.max_files),
        connect_timeout_s=_env_float("AIRLOCK_LIMIT_CONNECT_TIMEOUT", base.connect_timeout_s),
    )


DEFAULT_LIMITS = from_env()
