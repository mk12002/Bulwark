"""MCP connection + enumeration, and the normalized inventory model.

The analyzers operate on a transport-agnostic :class:`MCPInventory` (tools,
resources, prompts, plus transport/auth facts). :func:`enumerate_target`
produces one by connecting to a live server over stdio (a spawned command) or
SSE/HTTP (a URL). Airlock only *reads* tool metadata — it never invokes a tool.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from bulwark_core.limits import DEFAULT_LIMITS


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


_AUTH_QUERY_KEYS = ("token", "access_token", "api_key", "apikey", "key", "auth", "authorization")
_AUTH_ENV_VARS = ("MCP_AUTH_TOKEN", "MCP_API_KEY", "MCP_ACCESS_TOKEN", "MCP_BEARER_TOKEN")


def _remote_auth_present(target: str) -> bool:
    """Whether credentials appear to be supplied for a remote MCP target."""
    parsed = urlparse(target)
    if parsed.username or parsed.password:
        return True
    query = parse_qs(parsed.query)
    if any(key in query for key in _AUTH_QUERY_KEYS):
        return True
    return any(os.environ.get(var) for var in _AUTH_ENV_VARS)


def enumerate_target(target: str, timeout: float | None = None) -> MCPInventory:
    """Connect to ``target`` and return a populated inventory.

    Delegates to the async SDK client and runs it to completion under a hard
    ``timeout`` (default ``Limits.connect_timeout_s``, overridable via
    ``AIRLOCK_LIMIT_CONNECT_TIMEOUT``). Without it, a server that accepts the
    connection and never answers ``initialize`` hangs the scan forever — time is a
    resource like any other, and every other parse in the suite is bounded.

    Connection failures — including the timeout — are captured on
    ``inventory.connect_error`` rather than raised, so a partial/failed scan still
    renders and a corpus run does not abort on one unreachable server.
    """
    import anyio

    transport, is_remote, secure = classify_target(target)
    inventory = MCPInventory(
        target=target,
        transport=transport,
        is_remote=is_remote,
        secure_transport=secure,
        # stdio is a local pipe (no remote auth concept). For a remote target, look
        # for credentials actually supplied — userinfo in the URL, a token/key/auth
        # query parameter, or an MCP auth env var — rather than assuming their
        # absence, which would make "auth.missing" a synonym for "is remote".
        auth_present=not is_remote or _remote_auth_present(target),
    )
    budget = DEFAULT_LIMITS.connect_timeout_s if timeout is None else timeout
    try:
        anyio.run(_populate, inventory, target, budget)
    except TimeoutError:
        inventory.connect_error = (
            f"timed out after {budget:g}s connecting to or enumerating the server"
        )
    except Exception as exc:
        inventory.connect_error = f"{type(exc).__name__}: {exc}"
    return inventory


async def _populate(inventory: MCPInventory, target: str, timeout: float) -> None:
    import anyio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    with anyio.fail_after(timeout):
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
