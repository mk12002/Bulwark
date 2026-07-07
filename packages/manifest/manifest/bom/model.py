"""AIBOM IR — the inventory Manifest builds and maps to CycloneDX.

Findings/severity/report/AI come from ``bulwark_core``; this is the only
Manifest-specific data model. Components reference findings by id.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from bulwark_core import __version__ as _core_version
from pydantic import BaseModel, Field


class ComponentType(StrEnum):
    MODEL = "model"
    DATASET = "dataset"
    MCP_SERVER = "mcp-server"
    PROMPT = "prompt"
    TOOL = "tool"
    LIBRARY = "library"
    FRAMEWORK = "framework"
    AGENT = "agent"


LicenseRisk = Literal["ok", "restricted", "copyleft", "unknown"]


class License(BaseModel):
    id: str | None = None  # SPDX id if known
    name: str | None = None
    risk: LicenseRisk = "unknown"


class Provenance(BaseModel):
    source: str | None = None  # hf repo, pypi, url, local
    author: str | None = None
    version: str | None = None
    hash: str | None = None
    pinned: bool = False


class Component(BaseModel):
    key: str  # stable id (type + name + version)
    type: ComponentType
    name: str
    provenance: Provenance = Field(default_factory=Provenance)
    license: License = Field(default_factory=License)
    location: str | None = None  # where in the repo it was found
    findings: list[str] = Field(default_factory=list)  # Finding ids (B*/M*/P*/A*)
    metadata: dict = Field(default_factory=dict)


class Relationship(BaseModel):
    src: str
    rel: str  # "uses" | "wires" | "trained-on" | ...
    dst: str


class AIBOM(BaseModel):
    project: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    components: list[Component] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    bulwark_version: str = _core_version

    def by_type(self, ctype: ComponentType) -> list[Component]:
        return [c for c in self.components if c.type == ctype]

    def get(self, key: str) -> Component | None:
        return next((c for c in self.components if c.key == key), None)

    def add(self, component: Component) -> Component:
        """Add a component, merging into an existing one with the same key."""
        existing = self.get(component.key)
        if existing is None:
            self.components.append(component)
            return component
        # Merge: prefer richer provenance/license, union findings/metadata.
        if not existing.location:
            existing.location = component.location
        existing.metadata.update(component.metadata)
        return existing

    def type_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.components:
            counts[c.type.value] = counts.get(c.type.value, 0) + 1
        return counts
