"""Provenance normalization + secret scanning over the project.

Most provenance (source/version/hash/pinned) is set by the discoverers; this adds a
project-wide secret scan (B7) whose hits are attached to the closest component or a
synthetic project component.
"""

from __future__ import annotations

import re

from manifest.discover.base import DiscoveryContext

_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)(aws_secret_access_key|api[_-]?key|secret[_-]?key|password|token)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9/_\-]{12,}"
    ),
]
# Obvious placeholders that should NOT be flagged.
_PLACEHOLDER = re.compile(r"(?i)(your[_-]?|example|placeholder|xxxx|<.*>|changeme|dummy|redacted)")

_SCAN_SUFFIXES = {".py", ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".cfg", ".ini", ".sh"}


def find_secrets(ctx: DiscoveryContext) -> list[tuple[str, str]]:
    """Return (location, evidence) for likely secret references in the project."""
    hits: list[tuple[str, str]] = []
    for path in ctx.files:
        if path.suffix.lower() not in _SCAN_SUFFIXES and path.name.lower() != ".env":
            continue
        text = ctx.read_text(path)
        for rx in _TOKEN_PATTERNS:
            m = rx.search(text)
            if m and not _PLACEHOLDER.search(m.group(0)):
                hits.append((ctx.rel(path), f"possible secret in {ctx.rel(path)}"))
                break
    return hits
