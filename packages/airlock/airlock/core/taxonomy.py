"""The Airlock risk taxonomy: model (M1–M7) and MCP (P1–P9) categories.

Every :class:`~airlock.core.findings.Finding` maps to exactly one category here.
Each category carries a human title, a one-line description, its default severity,
and reference links (OWASP LLM Top 10 / MITRE ATLAS / CWE).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from airlock.core.severity import Severity


class Category(StrEnum):
    """Taxonomy codes. String-valued so findings can carry the code directly."""

    # Model artifact risks
    M1 = "M1"
    M2 = "M2"
    M3 = "M3"
    M4 = "M4"
    M5 = "M5"
    M6 = "M6"
    M7 = "M7"
    # MCP server risks
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"
    P6 = "P6"
    P7 = "P7"
    P8 = "P8"
    P9 = "P9"


@dataclass(frozen=True)
class CategoryInfo:
    """Static metadata about one taxonomy category."""

    code: Category
    target: str  # "model" | "mcp"
    title: str
    description: str
    default_severity: Severity
    references: tuple[str, ...] = field(default_factory=tuple)


_CATALOG: dict[Category, CategoryInfo] = {
    Category.M1: CategoryInfo(
        code=Category.M1,
        target="model",
        title="Arbitrary code execution via pickle deserialization",
        description=(
            "Pickle-based formats can execute arbitrary Python on load because the pickle "
            "VM can call arbitrary callables."
        ),
        default_severity=Severity.CRITICAL,
        references=("OWASP:LLM05", "CWE-502"),
    ),
    Category.M2: CategoryInfo(
        code=Category.M2,
        target="model",
        title="Unsafe deserialization surface",
        description=(
            "The artifact uses a deserialization mechanism that permits code execution even "
            "with no obvious payload present. The capability itself is the risk."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-502",),
    ),
    Category.M3: CategoryInfo(
        code=Category.M3,
        target="model",
        title="Suspicious payload signatures",
        description=(
            "Indicators of an embedded payload: networking, filesystem writes, shells, "
            "base64/marshal blobs, or dynamic import inside the artifact."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM05",),
    ),
    Category.M4: CategoryInfo(
        code=Category.M4,
        target="model",
        title="Risky serialization format",
        description=(
            "Model ships as pickle when a memory-safe format (safetensors) exists. Advisory."
        ),
        default_severity=Severity.MEDIUM,
        references=("best-practice",),
    ),
    Category.M5: CategoryInfo(
        code=Category.M5,
        target="model",
        title="Remote/custom code execution via config",
        description=(
            "config.json sets trust_remote_code:true or defines auto_map pointing to custom "
            "modeling_*.py / configuration_*.py, causing the framework to import repo Python."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM05", "CWE-494"),
    ),
    Category.M6: CategoryInfo(
        code=Category.M6,
        target="model",
        title="Archive smuggling",
        description=(
            "PyTorch artifacts are zip archives; extra executables, path-traversal member "
            "names, or unexpected file types may be smuggled inside."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-22", "CWE-506"),
    ),
    Category.M7: CategoryInfo(
        code=Category.M7,
        target="model",
        title="Provenance & integrity gaps",
        description=(
            "No signature, no published hash, missing/empty model card, or unverifiable "
            "author. The precondition for supply-chain compromise. Advisory."
        ),
        default_severity=Severity.LOW,
        references=("OWASP:LLM05", "SLSA"),
    ),
    Category.P1: CategoryInfo(
        code=Category.P1,
        target="mcp",
        title="Tool poisoning",
        description=(
            "A tool description or parameter docs contain instructions aimed at the agent. "
            "The description is the attack surface."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM01", "MITRE-ATLAS"),
    ),
    Category.P2: CategoryInfo(
        code=Category.P2,
        target="mcp",
        title="Injection via tool output",
        description=(
            "The server can return content crafted to hijack the agent when read back "
            "(indirect prompt injection)."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM01",),
    ),
    Category.P3: CategoryInfo(
        code=Category.P3,
        target="mcp",
        title="Hidden / obfuscated content",
        description=(
            "Zero-width characters, unicode tag characters, homoglyphs, RTL overrides, or "
            "comment tricks in tool names/descriptions."
        ),
        default_severity=Severity.HIGH,
        references=("CWE-176", "OWASP:LLM01"),
    ),
    Category.P4: CategoryInfo(
        code=Category.P4,
        target="mcp",
        title="Over-permissioned tools",
        description=(
            "Tools exposing shell execution, arbitrary filesystem read/write, raw network "
            "egress, or wildcard scopes."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM06", "CWE-269"),
    ),
    Category.P5: CategoryInfo(
        code=Category.P5,
        target="mcp",
        title="Confused deputy / cross-tool exfiltration",
        description=(
            "One tool can read sensitive data and another can send it outward, enabling "
            "unintended exfiltration."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM06", "OWASP:LLM02"),
    ),
    Category.P6: CategoryInfo(
        code=Category.P6,
        target="mcp",
        title="Secret / credential leakage",
        description=(
            "Credentials, tokens, or connection strings embedded in schemas/defaults, or "
            "tools that echo environment variables."
        ),
        default_severity=Severity.HIGH,
        references=("OWASP:LLM02", "CWE-798"),
    ),
    Category.P7: CategoryInfo(
        code=Category.P7,
        target="mcp",
        title="Rug-pull / TOFU risk",
        description=("A server can silently change tool definitions after the user approved them."),
        default_severity=Severity.MEDIUM,
        references=("CWE-494",),
    ),
    Category.P8: CategoryInfo(
        code=Category.P8,
        target="mcp",
        title="Insecure transport / weak auth",
        description="Plaintext transport, no authentication, or credentials passed insecurely.",
        default_severity=Severity.MEDIUM,
        references=("CWE-319", "CWE-306"),
    ),
    Category.P9: CategoryInfo(
        code=Category.P9,
        target="mcp",
        title="Tool shadowing / name collision",
        description=(
            "A tool name collides with or impersonates a well-known trusted tool to "
            "intercept calls."
        ),
        default_severity=Severity.MEDIUM,
        references=("CWE-706",),
    ),
}


def category_info(code: Category | str) -> CategoryInfo:
    """Look up static metadata for a category code.

    Accepts either a :class:`Category` or its string value (e.g. ``"M1"``).
    Raises ``KeyError`` for unknown codes.
    """
    key = code if isinstance(code, Category) else Category(code)
    return _CATALOG[key]


def all_categories() -> list[CategoryInfo]:
    """Return every category's metadata, in taxonomy order."""
    return list(_CATALOG.values())


def categories_for(target: str) -> list[CategoryInfo]:
    """Return category metadata for a scan target ('model' or 'mcp')."""
    return [c for c in _CATALOG.values() if c.target == target]
