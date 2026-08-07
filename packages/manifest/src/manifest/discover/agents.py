"""Agent discovery: agent config files → ``agent`` components (AI/Agent BOM).

Statically detects the agent-assembly shapes Warden also understands — a generic agent
manifest, an OpenAI Assistants config, or a CrewAI crew — and records each as an ``AGENT``
component whose metadata captures its autonomy, model, and tool names. This is what lets
the CycloneDX output carry agent components (aligned with the emerging CycloneDX Agent BOM
work), so an inventory reflects not just the parts but the *assemblies* wired from them.

Parsing is static; nothing is executed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register


def _load(ctx: DiscoveryContext, path: Path) -> Any:
    text = ctx.read_text(path)
    if not text.strip():
        return None
    try:
        if path.suffix.lower() == ".json":
            return json.loads(text)
        import yaml

        return yaml.safe_load(text)
    except Exception:  # malformed config is simply not an agent
        return None


def _tool_names(tools: Any) -> list[str]:
    names: list[str] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict):
                nm = t.get("name") or (t.get("function") or {}).get("name") or t.get("type")
                if nm:
                    names.append(str(nm))
            elif isinstance(t, str):
                names.append(t)
    return names


def _classify(data: Any) -> tuple[str, dict[str, Any]] | None:
    """Return (framework, agent_dict) if ``data`` is an agent config, else None."""
    if not isinstance(data, dict):
        return None
    # MCP client configs are handled by the mcp discoverer, not here.
    if "mcpServers" in data:
        return None
    # OpenAI Assistants
    if data.get("object") == "assistant" or ("instructions" in data and "tools" in data):
        return "openai_assistant", data
    # Generic agent manifest
    if "tools" in data and any(k in data for k in ("system_prompt", "autonomy", "model")):
        return "manifest", data
    # CrewAI: an "agents" mapping, or top-level role+goal entries
    agents = data.get("agents")
    if isinstance(agents, dict) and agents:
        return "crewai", data
    if all(isinstance(v, dict) and "role" in v and "goal" in v for v in data.values()) and data:
        return "crewai", data
    return None


def _component(
    path: Path, ctx: DiscoveryContext, framework: str, data: dict[str, Any]
) -> Component:
    name = str(data.get("name") or path.stem)
    tools = _tool_names(data.get("tools"))
    return Component(
        key=f"agent:{name}",
        type=ComponentType.AGENT,
        name=name,
        location=ctx.rel(path),
        provenance=Provenance(source=framework),
        metadata={
            "framework": framework,
            "autonomy": data.get("autonomy"),
            "model": data.get("model"),
            "tools": tools,
            "tool_count": len(tools),
            "has_system_prompt": bool(data.get("system_prompt") or data.get("instructions")),
        },
    )


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []
    for path in ctx.by_suffix(".yaml", ".yml", ".json"):
        data = _load(ctx, path)
        classified = _classify(data)
        if classified is None:
            continue
        framework, agent = classified
        out.append(_component(path, ctx, framework, agent))
    return out


register("agents", discover)
