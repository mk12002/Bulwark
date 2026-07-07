"""Prompt discovery: prompt files/templates and system prompts in configs."""

from __future__ import annotations

import json

import yaml

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register

_PROMPT_SUFFIXES = {".prompt", ".j2", ".jinja", ".jinja2"}


def _prompt_component(name: str, location: str, text: str, kind: str) -> Component:
    return Component(
        key=f"prompt:{location}:{name}",
        type=ComponentType.PROMPT,
        name=name,
        location=location,
        provenance=Provenance(source="local"),
        metadata={"kind": kind, "chars": len(text)},
    )


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []

    # Dedicated prompt template files, and anything under a prompts/ directory.
    for path in ctx.files:
        rel = ctx.rel(path)
        is_prompt_dir = "/prompts/" in f"/{rel}" or rel.startswith("prompts/")
        if path.suffix.lower() in _PROMPT_SUFFIXES or (
            is_prompt_dir and path.suffix.lower() in {".txt", ".md", ".json", ".yaml", ".yml"}
        ):
            out.append(_prompt_component(path.name, rel, ctx.read_text(path), "file"))

    # system_prompt fields inside YAML/JSON configs.
    for path in ctx.by_suffix(".yaml", ".yml", ".json"):
        text = ctx.read_text(path)
        try:
            data = yaml.safe_load(text) if path.suffix != ".json" else json.loads(text)
        except (yaml.YAMLError, json.JSONDecodeError):
            continue
        prompt = _find_system_prompt(data)
        if isinstance(prompt, str) and prompt.strip():
            out.append(_prompt_component("system_prompt", ctx.rel(path), prompt, "system_prompt"))
    return out


def _find_system_prompt(obj: object) -> str | None:
    if isinstance(obj, dict):
        for key in ("system_prompt", "system", "systemPrompt", "instructions"):
            if isinstance(obj.get(key), str):
                return obj[key]
        for v in obj.values():
            found = _find_system_prompt(v)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_system_prompt(item)
            if found:
                return found
    return None


register("prompts", discover)
