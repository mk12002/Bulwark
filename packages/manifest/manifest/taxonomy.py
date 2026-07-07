"""Manifest's governance taxonomy (B1–B9).

Registered into the shared ``bulwark_core`` registry at import. Imported risk from
Airlock (M*/P*) and Warden (A*) is surfaced as B5 but keeps its original codes.
"""

from __future__ import annotations

from enum import StrEnum

from bulwark_core.severity import Severity
from bulwark_core.taxonomy import (
    CategoryInfo,
    all_categories,
    categories_for,
    category_info,
    register_categories,
)

__all__ = ["Category", "CategoryInfo", "all_categories", "categories_for", "category_info"]


class Category(StrEnum):
    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B4 = "B4"
    B5 = "B5"
    B6 = "B6"
    B7 = "B7"
    B8 = "B8"
    B9 = "B9"


_CATEGORIES: list[CategoryInfo] = [
    CategoryInfo(
        code="B1",
        target="system",
        title="Undeclared / unpinned component",
        description="A model/dataset/dependency used without a pinned version or hash.",
        default_severity=Severity.MEDIUM,
        references=("SLSA", "supply-chain-hygiene"),
    ),
    CategoryInfo(
        code="B2",
        target="system",
        title="Missing provenance",
        description="A component with no verifiable source, author, or hash.",
        default_severity=Severity.MEDIUM,
        references=("NIST-AI-RMF", "SLSA"),
    ),
    CategoryInfo(
        code="B3",
        target="system",
        title="License risk",
        description=(
            "A restrictive, incompatible, or unknown license on a model, dataset, or dependency."
        ),
        default_severity=Severity.MEDIUM,
        references=("license-compliance",),
    ),
    CategoryInfo(
        code="B4",
        target="system",
        title="Known-vulnerable dependency",
        description="A dependency with a known advisory (via OSV).",
        default_severity=Severity.HIGH,
        references=("OSV",),
    ),
    CategoryInfo(
        code="B5",
        target="system",
        title="High-risk component (from Airlock/Warden)",
        description=(
            "A model/MCP server Airlock flagged, or an assembly Warden flagged, surfaced on "
            "the component."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM05", "OWASP:LLM06"),
    ),
    CategoryInfo(
        code="B6",
        target="system",
        title="Dataset governance gap",
        description="A dataset without documented source, license, or consent.",
        default_severity=Severity.MEDIUM,
        references=("NIST-AI-RMF", "data-governance"),
    ),
    CategoryInfo(
        code="B7",
        target="system",
        title="Secret / credential reference exposure",
        description="Hardcoded or broadly-scoped secrets referenced in the project.",
        default_severity=Severity.HIGH,
        references=("CWE-798",),
    ),
    CategoryInfo(
        code="B8",
        target="system",
        title="Unversioned / untracked prompt template",
        description="System/prompt templates lacking identifiers or version control.",
        default_severity=Severity.LOW,
        references=("governance-best-practice",),
    ),
    CategoryInfo(
        code="B9",
        target="system",
        title="Compliance control gap",
        description="A gap mapped against a control framework (e.g. NIST AI RMF). Advisory.",
        default_severity=Severity.LOW,
        references=("NIST-AI-RMF",),
    ),
]

register_categories(_CATEGORIES)
