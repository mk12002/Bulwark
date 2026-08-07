"""MCP server discovery: .mcp.json / client configs → mcp-server components."""

from __future__ import annotations

import json

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register


def _is_mcp_config(path_name: str) -> bool:
    lname = path_name.lower()
    return (
        lname == ".mcp.json"
        or ("mcp" in lname and lname.endswith(".json"))
        or ("claude_desktop_config" in lname)
    )


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []
    for path in ctx.by_suffix(".json"):
        if not _is_mcp_config(path.name):
            continue
        try:
            data = json.loads(ctx.read_text(path))
        except json.JSONDecodeError:
            continue
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            continue
        for name, cfg in servers.items():
            cmd = ""
            if isinstance(cfg, dict):
                cmd = cfg.get("command") or cfg.get("url") or ""
            out.append(
                Component(
                    key=f"mcp-server:{name}",
                    type=ComponentType.MCP_SERVER,
                    name=name,
                    location=ctx.rel(path),
                    provenance=Provenance(source=str(cmd) or "unknown"),
                    metadata={
                        "command": cfg.get("command") if isinstance(cfg, dict) else None,
                        "args": cfg.get("args") if isinstance(cfg, dict) else None,
                        "has_env": bool(isinstance(cfg, dict) and cfg.get("env")),
                    },
                )
            )
    return out


register("mcp", discover)
