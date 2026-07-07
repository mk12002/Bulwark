"""Secrets in the assembly (A6) and unscanned wired parts (A9)."""

from __future__ import annotations

import re

from bulwark_core.signals import SignalBundle

from warden.spec.model import AgentSpec

_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9/_\-]{12,}"),
]


def _scan_text(text: str) -> str | None:
    for rx in _TOKEN_PATTERNS:
        if rx.search(text):
            return rx.pattern
    return None


def collect(spec: AgentSpec, bundle: SignalBundle) -> None:
    """Emit A6 (embedded secret) and A9 (unscanned parts) signals."""
    haystacks: list[tuple[str, str]] = []
    if spec.system_prompt:
        haystacks.append(("system_prompt", spec.system_prompt))
    for t in spec.tools:
        haystacks.append((f"tool:{t.name}", "\n".join([t.description or "", *t.scopes])))
    for ds in spec.data_sources:
        haystacks.append((f"data:{ds.name}", ds.scope or ""))

    for where, text in haystacks:
        if _scan_text(text):
            bundle.add(
                "agent.embedded_secret",
                where,
                path=where,
                evidence=f"a credential/token appears embedded in the assembly at {where}",
            )

    if spec.mcp_servers:
        names = ", ".join(spec.mcp_servers[:5])
        bundle.add(
            "agent.unscanned_parts",
            names,
            path=names,
            evidence=(
                f"assembly wires {len(spec.mcp_servers)} MCP server(s) not verified by Airlock: "
                f"{names}"
            ),
        )
