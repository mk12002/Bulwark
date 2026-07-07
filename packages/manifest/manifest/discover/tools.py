"""Tool discovery: tool-spec files and agent tool definitions."""

from __future__ import annotations

import json

import yaml

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register


def _tool_component(name: str, location: str, description: str) -> Component:
    return Component(
        key=f"tool:{name}",
        type=ComponentType.TOOL,
        name=name,
        location=location,
        provenance=Provenance(source="local"),
        metadata={"description": description[:200]},
    )


def _extract_tools(data: object) -> list[tuple[str, str]]:
    """Return (name, description) for tools in OpenAI/Anthropic/manifest shapes."""
    items: list[dict] = []
    if isinstance(data, dict):
        for key in ("tools", "functions"):
            if isinstance(data.get(key), list):
                items = [i for i in data[key] if isinstance(i, dict)]
                break
    elif isinstance(data, list):
        items = [i for i in data if isinstance(i, dict)]

    out: list[tuple[str, str]] = []
    for item in items:
        obj: dict = item["function"] if isinstance(item.get("function"), dict) else item
        if isinstance(obj.get("toolSpec"), dict):
            obj = obj["toolSpec"]
        name = obj.get("name")
        if isinstance(name, str) and name:
            out.append((name, str(obj.get("description", ""))))
    return out


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []
    seen: set[str] = set()
    for path in ctx.by_suffix(".json", ".yaml", ".yml"):
        text = ctx.read_text(path)
        try:
            data = yaml.safe_load(text) if path.suffix != ".json" else json.loads(text)
        except (yaml.YAMLError, json.JSONDecodeError):
            continue
        for name, desc in _extract_tools(data):
            if name in seen:
                continue
            seen.add(name)
            out.append(_tool_component(name, ctx.rel(path), desc))
    return out


register("tools", discover)
