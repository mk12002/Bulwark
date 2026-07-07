"""Parse OpenAI/Anthropic/LangChain tool-definition files into an MCPInventory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from airlock.scanners.mcp.client import MCPInventory, ToolDef


class ToolSpecError(Exception):
    """Raised when a tool-spec file cannot be read or parsed."""


def load_toolspec(path: Path) -> MCPInventory:
    """Load a tool-spec file into an inventory the MCP analyzers can consume."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ToolSpecError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)  # YAML is a superset of JSON
    except yaml.YAMLError as exc:
        raise ToolSpecError(f"cannot parse {path}: {exc}") from exc
    if data is None:
        raise ToolSpecError(f"{path}: empty tool spec")

    tools = [_normalize(item) for item in _iter_tool_items(data)]
    tools = [t for t in tools if t is not None]
    return MCPInventory(
        target=str(path),
        transport="file",
        is_remote=False,
        secure_transport=True,
        auth_present=True,
        tools=[t for t in tools if t],
    )


def _iter_tool_items(data: Any) -> list[dict[str, Any]]:
    """Extract the list of tool objects from the various container shapes."""
    if isinstance(data, dict):
        for key in ("tools", "functions", "toolSpecs"):
            if isinstance(data.get(key), list):
                return [i for i in data[key] if isinstance(i, dict)]
        # A single tool object at the top level.
        if any(k in data for k in ("name", "function")):
            return [data]
        return []
    if isinstance(data, list):
        return [i for i in data if isinstance(i, dict)]
    return []


def _normalize(item: dict[str, Any]) -> ToolDef | None:
    """Normalize one tool object from any supported dialect into a ToolDef."""
    # OpenAI: {"type": "function", "function": {name, description, parameters}}
    if item.get("type") == "function" and isinstance(item.get("function"), dict):
        item = item["function"]
    # AWS Bedrock: {"toolSpec": {name, description, inputSchema: {json: {...}}}}
    if isinstance(item.get("toolSpec"), dict):
        item = item["toolSpec"]

    name = item.get("name")
    if not isinstance(name, str) or not name:
        return None
    description = item.get("description")
    description = description if isinstance(description, str) else ""

    schema = (
        item.get("input_schema")  # Anthropic / MCP
        or item.get("parameters")  # OpenAI
        or item.get("inputSchema")  # Bedrock / camelCase
        or item.get("args_schema")  # LangChain
        or {}
    )
    if isinstance(schema, dict) and isinstance(schema.get("json"), dict):
        schema = schema["json"]  # Bedrock wraps the JSON schema
    if not isinstance(schema, dict):
        schema = {}

    return ToolDef(name=name, description=description, input_schema=schema)
