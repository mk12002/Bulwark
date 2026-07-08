"""Discoverers: statically inventory a project into an AIBOM."""

from __future__ import annotations

from pathlib import Path

# Register built-in discoverers on import.
import manifest.discover.datasets
import manifest.discover.deps
import manifest.discover.mcp
import manifest.discover.models
import manifest.discover.notebooks
import manifest.discover.prompts
import manifest.discover.tools  # noqa: F401
from manifest.bom.model import AIBOM
from manifest.discover.base import DiscoveryContext, registered

__all__ = ["DiscoveryContext", "discover_from_ctx", "discover_project"]


def discover_from_ctx(ctx: DiscoveryContext) -> AIBOM:
    """Run every discoverer over an already-built context and merge into one AIBOM."""
    bom = AIBOM(project=ctx.root.name or str(ctx.root))
    for _name, fn in registered():
        for component in fn(ctx):
            bom.add(component)
    return bom


def discover_project(root: Path) -> AIBOM:
    """Run every discoverer over a project directory and merge into one AIBOM."""
    return discover_from_ctx(DiscoveryContext.build(root))
