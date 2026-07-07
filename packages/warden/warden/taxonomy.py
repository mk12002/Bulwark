"""Warden's excessive-agency taxonomy (A1–A10).

Registered into the shared ``bulwark_core`` registry at import so the rule loader
validates ``A*`` categories and reporters can look up titles/references.
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

__all__ = [
    "Category",
    "CategoryInfo",
    "all_categories",
    "categories_for",
    "category_info",
]


class Category(StrEnum):
    """Warden taxonomy codes."""

    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"
    A5 = "A5"
    A6 = "A6"
    A7 = "A7"
    A8 = "A8"
    A9 = "A9"
    A10 = "A10"


_CATEGORIES: list[CategoryInfo] = [
    CategoryInfo(
        code="A1",
        target="agent",
        title="Excessive tool scope",
        description=(
            "A tool granted broader capability than needed — filesystem root, unrestricted "
            "shell, wildcard network, or '*' resource scopes."
        ),
        default_severity=Severity.MEDIUM,
        references=("OWASP:LLM06", "CWE-269"),
    ),
    CategoryInfo(
        code="A2",
        target="agent",
        title="Dangerous tool combination (toxic combination)",
        description=(
            "Individually acceptable tools that together form a harmful path — a sensitive "
            "source reachable to an egress sink (the flagship confused-deputy check)."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM06", "OWASP:LLM02"),
    ),
    CategoryInfo(
        code="A3",
        target="agent",
        title="Missing human-in-the-loop on high-impact actions",
        description=(
            "Irreversible/destructive/financial/external-communication tools with no "
            "confirmation or approval gate."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM06",),
    ),
    CategoryInfo(
        code="A4",
        target="agent",
        title="Over-broad system-prompt authority / weak guardrails",
        description=(
            "System prompt grants open-ended autonomy, lacks refusal/limits, or is itself "
            "injectable/ambiguous."
        ),
        default_severity=Severity.MEDIUM,
        references=("OWASP:LLM01", "OWASP:LLM06"),
    ),
    CategoryInfo(
        code="A5",
        target="agent",
        title="Unrestricted egress / exfiltration surface",
        description=(
            "The agent can reach arbitrary URLs or send data outward without allow-listing, "
            "in the presence of a sensitive source."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM02",),
    ),
    CategoryInfo(
        code="A6",
        target="agent",
        title="Secrets/credentials in the assembly",
        description=(
            "API keys/tokens embedded in configs or broadly injected into many tools' environments."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-798", "OWASP:LLM02"),
    ),
    CategoryInfo(
        code="A7",
        target="agent",
        title="Excessive data/memory access",
        description=(
            "The agent has read access to more data (files, DBs, long-lived memory, "
            "whole-drive context) than its stated purpose requires."
        ),
        default_severity=Severity.MEDIUM,
        references=("OWASP:LLM06",),
    ),
    CategoryInfo(
        code="A8",
        target="agent",
        title="Unsandboxed code/shell execution",
        description="Code-exec or shell tools without a declared sandbox / isolation boundary.",
        default_severity=Severity.HIGH,
        references=("CWE-250",),
    ),
    CategoryInfo(
        code="A9",
        target="agent",
        title="Untrusted/unscanned parts wired in",
        description=(
            "The assembly references MCP servers/models that have not passed Airlock "
            "(scan them with --scan-parts)."
        ),
        default_severity=Severity.MEDIUM,
        references=("OWASP:LLM05",),
    ),
    CategoryInfo(
        code="A10",
        target="agent",
        title="No runaway guards",
        description=("An autonomous/looping agent with no iteration cap, budget, or timeout."),
        default_severity=Severity.MEDIUM,
        references=("OWASP:LLM06",),
    ),
]

register_categories(_CATEGORIES)
