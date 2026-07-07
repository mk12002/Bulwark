"""Capability classification entry points (thin re-export of the normalize lexicon)."""

from __future__ import annotations

from warden.spec.model import AgentSpec, Capability
from warden.spec.normalize import classify_tool, has_wildcard_scope

__all__ = ["capability_histogram", "classify_tool", "has_wildcard_scope"]


def capability_histogram(spec: AgentSpec) -> dict[Capability, int]:
    """Count how many tools expose each capability."""
    counts: dict[Capability, int] = {}
    for tool in spec.tools:
        for cap in tool.capabilities:
            counts[cap] = counts.get(cap, 0) + 1
    return counts
