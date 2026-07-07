"""MCP connection + enumeration, and the normalized inventory model.

The analyzers operate on a transport-agnostic :class:`MCPInventory` (tools,
resources, prompts, plus transport/auth facts). :func:`enumerate_target`
produces one by connecting to a live server over stdio (a spawned command) or
SSE/HTTP (a URL). Airlock only *reads* tool metadata — it never invokes a tool.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class ToolDef:
    """A normalized MCP tool definition."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None

    def param_docs(self) -> list[tuple[str, str]]:
        """Return (param_name, description) pairs from the input schema."""
        props = self.input_schema.get("properties")
        out: list[tuple[str, str]] = []
        if isinstance(props, dict):
            for pname, spec in props.items():
                if isinstance(spec, dict) and isinstance(spec.get("description"), str):
                    out.append((pname, spec["description"]))
        return out

    def all_text(self) -> str:
        """Name + description + parameter docs, for capability heuristics."""
        parts = [self.name, self.description]
        parts.extend(doc for _n, doc in self.param_docs())
        return "\n".join(p for p in parts if p)


@dataclass
class ResourceDef:
    name: str
    uri: str
    description: str = ""


@dataclass
class PromptDef:
    name: str
    description: str = ""


@dataclass
class MCPInventory:
    """Everything a scan needs to know about one MCP server."""

    target: str
    transport: str  # "stdio" | "sse" | "http"
    is_remote: bool
    secure_transport: bool
    auth_present: bool
    tools: list[ToolDef] = field(default_factory=list)
    resources: list[ResourceDef] = field(default_factory=list)
    prompts: list[PromptDef] = field(default_factory=list)
    connect_error: str | None = None


class ConnectError(Exception):
    """Raised when Airlock cannot connect to or enumerate an MCP server."""


def classify_target(target: str) -> tuple[str, bool, bool]:
    """Return (transport, is_remote, secure_transport) for a target string."""
    parsed = urlparse(target)
    scheme = parsed.scheme.lower()
    if scheme in ("http", "https", "sse"):
        transport = "sse" if scheme == "sse" else "http"
        secure = scheme == "https"
        return transport, True, secure
    if scheme in ("ws", "wss"):
        return "http", True, scheme == "wss"
    # Anything else is a command to spawn over stdio (a local pipe).
    return "stdio", False, True


def _split_command(target: str) -> list[str]:
    """Split a stdio command string into argv, tolerating Windows paths.

    ``shlex`` in POSIX mode mangles backslashes; in non-POSIX mode it keeps the
    surrounding quotes on each token. We use non-POSIX and then strip a single
    pair of matching surrounding quotes from each token.
    """
    parts = shlex.split(target, posix=False)
    cleaned: list[str] = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'":
            cleaned.append(part[1:-1])
        else:
            cleaned.append(part)
    return cleaned


def enumerate_target(target: str, timeout: float = 20.0) -> MCPInventory:
    """Connect to ``target`` and return a populated inventory.

    Delegates to the async SDK client and runs it to completion. Connection
    failures are captured on ``inventory.connect_error`` rather than raised, so a
    partial/failed scan still renders.
    """
    import anyio

    transport, is_remote, secure = classify_target(target)
    inventory = MCPInventory(
        target=target,
        transport=transport,
        is_remote=is_remote,
        secure_transport=secure,
        # stdio is a local pipe (no remote auth concept); remote needs explicit auth.
        auth_present=not is_remote,
    )
    try:
        anyio.run(_populate, inventory, target, timeout)
    except Exception as exc:
        inventory.connect_error = f"{type(exc).__name__}: {exc}"
    return inventory


async def _populate(inventory: MCPInventory, target: str, timeout: float) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    if inventory.transport == "stdio":
        parts = _split_command(target)
        if not parts:
            raise ConnectError("empty stdio command")
        params = StdioServerParameters(command=parts[0], args=parts[1:])
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            await _collect(session, inventory)
    else:
        from mcp.client.sse import sse_client

        async with (
            sse_client(target) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            await _collect(session, inventory)


async def _collect(session: Any, inventory: MCPInventory) -> None:
    tools = await session.list_tools()
    for t in tools.tools:
        inventory.tools.append(
            ToolDef(
                name=t.name,
                description=t.description or "",
                input_schema=dict(t.inputSchema or {}),
                output_schema=_maybe_dict(getattr(t, "outputSchema", None)),
            )
        )
    inventory.resources = await _safe_resources(session)
    inventory.prompts = await _safe_prompts(session)


def _maybe_dict(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, dict) and value else None


async def _safe_resources(session: Any) -> list[ResourceDef]:
    try:
        res = await session.list_resources()
    except Exception:
        return []
    return [
        ResourceDef(name=r.name or "", uri=str(r.uri), description=r.description or "")
        for r in res.resources
    ]


async def _safe_prompts(session: Any) -> list[PromptDef]:
    try:
        res = await session.list_prompts()
    except Exception:
        return []
    return [PromptDef(name=p.name or "", description=p.description or "") for p in res.prompts]
