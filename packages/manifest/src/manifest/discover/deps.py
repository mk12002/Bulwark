"""Dependency discovery: requirements.txt, pyproject.toml, package.json."""

from __future__ import annotations

import re
import tomllib

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register

# Libraries that make a dependency an AI/ML framework component (vs a plain library).
_AI_FRAMEWORKS = {
    "torch",
    "tensorflow",
    "transformers",
    "diffusers",
    "sentence-transformers",
    "langchain",
    "langgraph",
    "llama-index",
    "llama_index",
    "openai",
    "anthropic",
    "cohere",
    "mcp",
    "crewai",
    "autogen",
    "vllm",
    "onnxruntime",
    "safetensors",
    "huggingface-hub",
    "huggingface_hub",
    "ollama",
    "keras",
    "scikit-learn",
    "sklearn",
}

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]+)?")


def _component(name: str, version: str | None, pinned: bool, location: str) -> Component:
    canon = name.lower().replace("_", "-")
    ctype = ComponentType.FRAMEWORK if canon in _AI_FRAMEWORKS else ComponentType.LIBRARY
    return Component(
        key=f"pypi:{canon}@{version or '*'}",
        type=ctype,
        name=canon,
        location=location,
        provenance=Provenance(source="pypi", version=version, pinned=pinned),
        metadata={"ecosystem": "PyPI"},
    )


def _parse_requirements(text: str, location: str) -> list[Component]:
    out: list[Component] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(2), m.group(3)
        pinned = op == "==" and bool(ver)
        out.append(_component(name, ver if op else None, pinned, location))
    return out


def _parse_pyproject(text: str, location: str) -> list[Component]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    deps: list[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        deps += project.get("dependencies", []) or []
        for extra in (project.get("optional-dependencies", {}) or {}).values():
            deps += extra or []
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        for name, spec in (poetry.get("dependencies", {}) or {}).items():
            if name.lower() == "python":
                continue
            ver = spec if isinstance(spec, str) else None
            deps.append(f"{name} {ver}" if ver else name)
    out: list[Component] = []
    for dep in deps:
        m = _REQ_LINE.match(str(dep))
        if m:
            name, op, ver = m.group(1), m.group(2), m.group(3)
            out.append(_component(name, ver if op else None, op == "==" and bool(ver), location))
    return out


def _parse_package_json(text: str, location: str) -> list[Component]:
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[Component] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section, {}) or {}).items():
            clean = str(ver).lstrip("^~>=< ")
            pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+", clean))
            out.append(
                Component(
                    key=f"npm:{name}@{clean or '*'}",
                    type=ComponentType.LIBRARY,
                    name=name,
                    location=location,
                    provenance=Provenance(source="npm", version=clean or None, pinned=pinned),
                    metadata={"ecosystem": "npm"},
                )
            )
    return out


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []
    for path in ctx.by_name("requirements.txt", "requirements-dev.txt"):
        out += _parse_requirements(ctx.read_text(path), ctx.rel(path))
    for path in ctx.by_name("pyproject.toml"):
        out += _parse_pyproject(ctx.read_text(path), ctx.rel(path))
    for path in ctx.by_name("package.json"):
        out += _parse_package_json(ctx.read_text(path), ctx.rel(path))
    return out


register("deps", discover)
