"""Importer registry: detect the config shape and dispatch to an importer.

Each importer registers a ``(name, detect, load)`` triple. ``detect`` inspects the
parsed data; ``load`` converts it into an :class:`AgentSpec`. Importers never
execute target code — they parse statically.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from warden.spec.model import AgentSpec
from warden.spec.normalize import normalize


class ImportError_(Exception):
    """Raised when a config cannot be read or imported into an AgentSpec."""


Detect = Callable[[Path, Any], bool]
Load = Callable[[Path, Any], AgentSpec]


@dataclass
class Importer:
    name: str
    detect: Detect
    load: Load


_REGISTRY: list[Importer] = []


def register(name: str, detect: Detect, load: Load) -> None:
    """Register an importer (idempotent by name)."""
    global _REGISTRY
    _REGISTRY = [i for i in _REGISTRY if i.name != name]
    _REGISTRY.append(Importer(name=name, detect=detect, load=load))


def _parse(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ImportError_(f"cannot read {path}: {exc}") from exc
    try:
        return yaml.safe_load(text)  # YAML is a JSON superset
    except yaml.YAMLError as exc:
        raise ImportError_(f"cannot parse {path}: {exc}") from exc


def import_agent(path: Path) -> tuple[AgentSpec, str]:
    """Detect the config type, import it, normalize, and return (spec, importer)."""
    # Ensure built-in importers are registered.
    import warden.importers.manifest_yaml
    import warden.importers.mcp_config  # noqa: F401

    data = _parse(path)
    if data is None:
        raise ImportError_(f"{path}: empty config")
    for importer in _REGISTRY:
        if importer.detect(path, data):
            return normalize(importer.load(path, data)), importer.name
    raise ImportError_(
        f"{path}: no importer recognized this config "
        f"(tried: {', '.join(i.name for i in _REGISTRY)})"
    )
