"""Import an MCP client config (``.mcp.json`` / ``claude_desktop_config.json``).

These declare which MCP servers a client wires in. The individual tools each server
exposes are only known by connecting (that is Airlock's job), so the resulting
AgentSpec records the servers as references — which trips A9 (unscanned parts) and
feeds ``--scan-parts``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from warden.importers.base import ImportError_, register
from warden.spec.model import AgentSpec


def detect(path: Path, data: Any) -> bool:
    return isinstance(data, dict) and "mcpServers" in data


def load(path: Path, data: Any) -> AgentSpec:
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        raise ImportError_(f"{path}: 'mcpServers' must be a mapping")
    refs: list[str] = []
    for name, cfg in servers.items():
        if isinstance(cfg, dict) and cfg.get("command"):
            args = " ".join(cfg.get("args", []) or [])
            refs.append(f"{name}: {cfg['command']} {args}".strip())
        elif isinstance(cfg, dict) and cfg.get("url"):
            refs.append(f"{name}: {cfg['url']}")
        else:
            refs.append(name)
    return AgentSpec(name=data.get("name", path.stem), mcp_servers=refs, autonomy="assisted")


register("mcp_config", detect, load)
