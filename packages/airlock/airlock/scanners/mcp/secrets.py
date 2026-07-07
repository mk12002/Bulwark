"""Secret / credential leakage detection over schemas and defaults (P6).

Combines known token-format regexes with a Shannon-entropy check over string
defaults/enums in tool input schemas, plus an env-echo heuristic.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from airlock.core.signals import SignalBundle
from airlock.scanners.mcp.client import MCPInventory, ToolDef

# High-signal token formats. Kept conservative to limit false positives.
_TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "openai-key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "private-key-block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
    "connection-string": re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^\s\"']*:[^\s\"']+@"),
}

_ENV_ECHO_RE = re.compile(
    r"(echo|return|dump|print|expose|list).{0,20}(environment|env[_ ]?var|os\.environ|getenv)"
    r"|(all|the) environment variables",
    re.IGNORECASE,
)

_ENTROPY_THRESHOLD = 4.0
_MIN_SECRET_LEN = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret(value: str) -> bool:
    if len(value) < _MIN_SECRET_LEN:
        return False
    # Long, high-entropy, mostly token-ish characters.
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-\.]+", value):
        return False
    return _shannon_entropy(value) >= _ENTROPY_THRESHOLD


def _iter_strings(obj: Any, path: str = "") -> list[tuple[str, str]]:
    """Yield (json_path, string_value) for every string in a nested structure."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((path or "$", obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_iter_strings(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_iter_strings(v, f"{path}[{i}]"))
    return out


def _scan_tool(tool: ToolDef, bundle: SignalBundle) -> None:
    for json_path, value in _iter_strings(tool.input_schema):
        # Skip 'description' fields — those are P1/P3 territory, not secrets.
        if json_path.endswith("description") or json_path.endswith("title"):
            continue
        for kind, rx in _TOKEN_PATTERNS.items():
            if rx.search(value):
                bundle.add(
                    "secret.finding",
                    f"{kind}:{json_path}",
                    path=tool.name,
                    detail=json_path,
                    evidence=f"{kind} in schema at {json_path}",
                )
                break
        else:
            if _looks_like_secret(value):
                bundle.add(
                    "secret.finding",
                    f"high-entropy:{json_path}",
                    path=tool.name,
                    detail=json_path,
                    evidence=f"high-entropy string in schema at {json_path}",
                )

    if _ENV_ECHO_RE.search(tool.all_text()):
        bundle.add(
            "tool.env_echo",
            True,
            path=tool.name,
            evidence=f"{tool.name} advertises echoing environment variables",
        )


def collect(inventory: MCPInventory, bundle: SignalBundle) -> None:
    """Emit P6 signals for embedded secrets and env-echo behaviour."""
    for tool in inventory.tools:
        _scan_tool(tool, bundle)
