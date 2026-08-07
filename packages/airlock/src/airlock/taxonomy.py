"""The Airlock risk taxonomy: model (M1–M7) and MCP (P1–P9) categories.

Airlock's category codes are registered into the shared ``bulwark_core`` registry
at import, so the rule loader can validate them and reporters can look up titles/
references. Importing :mod:`airlock` triggers this registration.
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
    """Airlock taxonomy codes. String-valued so findings carry the code directly."""

    M1 = "M1"
    M2 = "M2"
    M3 = "M3"
    M4 = "M4"
    M5 = "M5"
    M6 = "M6"
    M7 = "M7"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"
    P6 = "P6"
    P7 = "P7"
    P8 = "P8"
    P9 = "P9"


_CATEGORIES: list[CategoryInfo] = [
    CategoryInfo(
        code="M1",
        target="model",
        title="Arbitrary code execution via pickle deserialization",
        description=(
            "Pickle-based formats can execute arbitrary Python on load because the pickle "
            "VM can call arbitrary callables."
        ),
        default_severity=Severity.CRITICAL,
        references=("OWASP:LLM03:2025", "CWE-502"),
    ),
    CategoryInfo(
        code="M2",
        target="model",
        title="Unsafe deserialization surface",
        description=(
            "The artifact uses a deserialization mechanism that permits code execution even "
            "with no obvious payload present. The capability itself is the risk."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-502",),
    ),
    CategoryInfo(
        code="M3",
        target="model",
        title="Suspicious payload signatures",
        description=(
            "Indicators of an embedded payload: networking, filesystem writes, shells, "
            "base64/marshal blobs, or dynamic import inside the artifact."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM03:2025",),
    ),
    CategoryInfo(
        code="M4",
        target="model",
        title="Risky serialization format",
        description=(
            "Model ships as pickle when a memory-safe format (safetensors) exists. Advisory."
        ),
        default_severity=Severity.MEDIUM,
        references=("safetensors", "CWE-502",),
    ),
    CategoryInfo(
        code="M5",
        target="model",
        title="Remote/custom code execution via config",
        description=(
            "config.json sets trust_remote_code:true or defines auto_map pointing to custom "
            "modeling_*.py / configuration_*.py, causing the framework to import repo Python."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM03:2025", "CWE-494"),
    ),
    CategoryInfo(
        code="M6",
        target="model",
        title="Archive smuggling",
        description=(
            "PyTorch artifacts are zip archives; extra executables, path-traversal member "
            "names, or unexpected file types may be smuggled inside."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-22", "CWE-506"),
    ),
    CategoryInfo(
        code="M7",
        target="model",
        title="Provenance & integrity gaps",
        description=(
            "No signature, no published hash, missing/empty model card, or unverifiable "
            "author. The precondition for supply-chain compromise. Advisory."
        ),
        default_severity=Severity.LOW,
        references=("OWASP:LLM03:2025", "SLSA"),
    ),
    CategoryInfo(
        code="P1",
        target="mcp",
        title="Tool poisoning",
        description=(
            "A tool description or parameter docs contain instructions aimed at the agent. "
            "The description is the attack surface."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM01:2025", "MITRE-ATLAS"),
    ),
    CategoryInfo(
        code="P2",
        target="mcp",
        title="Injection via tool output",
        description=(
            "The server can return content crafted to hijack the agent when read back "
            "(indirect prompt injection)."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM01:2025",),
    ),
    CategoryInfo(
        code="P3",
        target="mcp",
        title="Hidden / obfuscated content",
        description=(
            "Zero-width characters, unicode tag characters, homoglyphs, RTL overrides, or "
            "comment tricks in tool names/descriptions."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-176", "OWASP:LLM01:2025"),
    ),
    CategoryInfo(
        code="P4",
        target="mcp",
        title="Over-permissioned tools",
        description=(
            "Tools exposing shell execution, arbitrary filesystem read/write, raw network "
            "egress, or wildcard scopes."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM06:2025", "CWE-269"),
    ),
    CategoryInfo(
        code="P5",
        target="mcp",
        title="Confused deputy / cross-tool exfiltration",
        description=(
            "One tool can read sensitive data and another can send it outward, enabling "
            "unintended exfiltration."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM06:2025", "OWASP:LLM02:2025"),
    ),
    CategoryInfo(
        code="P6",
        target="mcp",
        title="Secret / credential leakage",
        description=(
            "Credentials, tokens, or connection strings embedded in schemas/defaults, or "
            "tools that echo environment variables."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM02:2025", "CWE-798"),
    ),
    CategoryInfo(
        code="P7",
        target="mcp",
        title="Rug-pull / TOFU risk",
        description="A server can silently change tool definitions after the user approved them.",
        default_severity=Severity.MEDIUM,
        references=("CWE-494",),
    ),
    CategoryInfo(
        code="P8",
        target="mcp",
        title="Insecure transport / weak auth",
        description="Plaintext transport, no authentication, or credentials passed insecurely.",
        default_severity=Severity.MEDIUM,
        references=("CWE-319", "CWE-306"),
    ),
    CategoryInfo(
        code="P9",
        target="mcp",
        title="Tool shadowing / name collision",
        description=(
            "A tool name collides with or impersonates a well-known trusted tool to "
            "intercept calls."
        ),
        default_severity=Severity.MEDIUM,
        references=("CWE-706",),
    ),
]

register_categories(_CATEGORIES)
