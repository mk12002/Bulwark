"""Severity enum and normalization/scoring helpers.

Kept separate from :mod:`airlock.core.findings` so that scoring logic and the
severity ordering can be reused without importing the full finding model.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Ordered severity levels. String-valued for clean JSON serialization."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank, higher is worse. Useful for comparison and sorting."""
        return _RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def parse_severity(value: str) -> Severity:
    """Parse a case-insensitive severity string, raising ``ValueError`` if unknown."""
    try:
        return Severity(value.strip().lower())
    except ValueError as exc:  # pragma: no cover - trivial re-raise
        valid = ", ".join(s.value for s in Severity)
        raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc


def worst_of(severities: list[Severity]) -> Severity:
    """Return the highest severity in a list, or INFO when empty."""
    return max(severities, default=Severity.INFO)
