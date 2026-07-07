"""AgentSpec IR — the single normalized shape every importer produces.

All analysis runs on this IR, so adding a framework importer never touches the
analysis engine. Findings/severity come from ``bulwark_core``; this is the only
Warden-specific data model.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Capability(StrEnum):
    """What a tool can do, once normalized. Used by the graph and rules."""

    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    SHELL = "shell"
    CODE_EXEC = "code_exec"
    NET_OUT = "net_out"
    NET_IN = "net_in"
    SECRET_READ = "secret_read"
    DB_READ = "db_read"
    DB_WRITE = "db_write"
    EMAIL_SEND = "email_send"
    FINANCIAL = "financial"
    DESTRUCTIVE = "destructive"
    BROWSE = "browse"
    MEMORY_WRITE = "memory_write"
    UNKNOWN = "unknown"


class Gate(StrEnum):
    """Human-in-the-loop gate on a tool's invocation."""

    NONE = "none"
    CONFIRM = "confirm"
    APPROVAL = "approval"
    DRY_RUN = "dry_run"


# Capabilities that read data an attacker would want to exfiltrate.
SOURCE_CAPS = frozenset(
    {Capability.FS_READ, Capability.SECRET_READ, Capability.DB_READ, Capability.BROWSE}
)
# Capabilities that can move data off the host / act on the outside world.
SINK_CAPS = frozenset(
    {Capability.NET_OUT, Capability.FS_WRITE, Capability.EMAIL_SEND, Capability.DB_WRITE}
)
# High-impact capabilities that should require a human gate.
HIGH_IMPACT_CAPS = frozenset(
    {
        Capability.SHELL,
        Capability.CODE_EXEC,
        Capability.FS_WRITE,
        Capability.DESTRUCTIVE,
        Capability.FINANCIAL,
        Capability.EMAIL_SEND,
        Capability.DB_WRITE,
    }
)
# Capabilities that execute arbitrary code and want an explicit sandbox.
EXEC_CAPS = frozenset({Capability.SHELL, Capability.CODE_EXEC})


class Tool(BaseModel):
    """One tool wired into the agent."""

    name: str
    source: str | None = None  # which MCP server / plugin provided it
    description: str | None = None
    scopes: list[str] = Field(default_factory=list)  # raw scope strings from config
    capabilities: set[Capability] = Field(default_factory=set)  # filled by normalize
    sandboxed: bool | None = None
    gate: Gate = Gate.NONE


class DataSource(BaseModel):
    """A data source the agent can read."""

    name: str
    kind: str  # files | db | memory | context | env
    scope: str | None = None
    sensitive: bool = False


class Limits(BaseModel):
    """Runaway guards on an autonomous agent."""

    max_iterations: int | None = None
    budget: float | None = None
    timeout_s: int | None = None

    def any_set(self) -> bool:
        return any(v is not None for v in (self.max_iterations, self.budget, self.timeout_s))


class AgentSpec(BaseModel):
    """The normalized agent assembly."""

    name: str
    model: str | None = None
    system_prompt: str | None = None
    tools: list[Tool] = Field(default_factory=list)
    data_sources: list[DataSource] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)  # references → A9 / --scan-parts
    limits: Limits = Field(default_factory=Limits)
    autonomy: Literal["manual", "assisted", "autonomous"] = "assisted"

    def all_capabilities(self) -> set[Capability]:
        caps: set[Capability] = set()
        for t in self.tools:
            caps |= t.capabilities
        return caps

    def summary(self) -> str:
        """A one-line normalized summary for ``warden import`` / audit headers."""
        caps = sorted(c.value for c in self.all_capabilities())
        return (
            f"agent '{self.name}' — model={self.model or '?'} autonomy={self.autonomy} "
            f"tools={len(self.tools)} data_sources={len(self.data_sources)} "
            f"mcp_servers={len(self.mcp_servers)} caps=[{', '.join(caps)}]"
        )
