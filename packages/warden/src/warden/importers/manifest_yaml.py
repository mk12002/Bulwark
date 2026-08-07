"""Import a generic agent manifest (YAML or JSON) into an AgentSpec.

This is Warden's canonical, documented schema — also the way a user describes an
agent Warden can't otherwise parse. Keys mirror the AgentSpec IR:

    name, model, system_prompt, autonomy,
    tools: [{name, source, description, scopes, sandboxed, gate}],
    data_sources: [{name, kind, scope, sensitive}],
    mcp_servers: [...], limits: {max_iterations, budget, timeout_s}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from warden.importers.base import ImportError_, register
from warden.spec.model import AgentSpec


def detect(path: Path, data: Any) -> bool:
    """A mapping with tools/data_sources/system_prompt — but not a more specific shape."""
    if not isinstance(data, dict):
        return False
    # Defer to the specific importers for their shapes.
    if data.get("object") == "assistant" or "instructions" in data or "mcpServers" in data:
        return False
    if any(isinstance(v, dict) and "role" in v and "goal" in v for v in data.values()):
        return False  # CrewAI
    return any(k in data for k in ("tools", "data_sources", "system_prompt", "agent"))


def load(path: Path, data: Any) -> AgentSpec:
    if not isinstance(data, dict):
        raise ImportError_(f"{path}: expected a mapping at the top level")
    # Allow a single {"agent": {...}} wrapper.
    if "agent" in data and isinstance(data["agent"], dict):
        data = data["agent"]
    data.setdefault("name", path.stem)
    try:
        return AgentSpec.model_validate(data)
    except Exception as exc:  # pydantic ValidationError and friends
        raise ImportError_(f"{path}: invalid agent manifest: {exc}") from exc


register("manifest", detect, load)


def parse_file(path: Path) -> AgentSpec:
    """Convenience: read + parse a manifest file directly."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return load(path, data)
