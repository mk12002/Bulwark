"""A tool-agnostic category registry for the Bulwark suite.

Each tool registers its own taxonomy codes (Airlock: ``M*``/``P*``; Warden: ``A*``;
Manifest: ``B*``) into a shared registry with titles, default severities, and
references. The rule loader validates rule categories against what is registered.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from bulwark_core.severity import Severity


@dataclass(frozen=True)
class CategoryInfo:
    """Static metadata about one taxonomy category."""

    code: str
    target: str  # the tool's domain, e.g. "model" | "mcp" | "agent"
    title: str
    description: str
    default_severity: Severity
    references: tuple[str, ...] = field(default_factory=tuple)


_REGISTRY: dict[str, CategoryInfo] = {}


def register_categories(infos: Iterable[CategoryInfo]) -> None:
    """Register (or replace) category metadata. Idempotent per code."""
    for info in infos:
        _REGISTRY[info.code] = info


def category_info(code: str) -> CategoryInfo:
    """Look up metadata for a category code. Raises ``KeyError`` if unknown."""
    return _REGISTRY[str(code)]


def is_known(code: str) -> bool:
    """Whether a category code has been registered by some tool."""
    return str(code) in _REGISTRY


def all_categories() -> list[CategoryInfo]:
    """Return every registered category's metadata, in registration order."""
    return list(_REGISTRY.values())


def categories_for(target: str) -> list[CategoryInfo]:
    """Return registered category metadata for a given target/domain."""
    return [c for c in _REGISTRY.values() if c.target == target]
