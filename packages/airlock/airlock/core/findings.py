"""Core pydantic data model: Location, Finding, and ScanResult.

These are the stable, machine-readable shapes every scanner produces and every
reporter consumes. Severity lives in :mod:`airlock.core.severity`.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from airlock import __version__
from airlock.core.severity import Severity, worst_of

Confidence = Literal["low", "medium", "high"]
Source = Literal["rule", "analyzer", "ai"]
TargetType = Literal["model", "mcp"]


class Location(BaseModel):
    """Where a finding was observed."""

    target: str
    path: str | None = None  # file / tool name / json pointer
    detail: str | None = None  # opcode index, line, member name...


class Finding(BaseModel):
    """A single explainable security finding."""

    id: str  # stable, e.g. "M1-pickle-reduce-os-system"
    category: str  # taxonomy code: "M1".."M7" / "P1".."P9"
    title: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: str  # the concrete thing found (truncated, safe)
    rationale: str  # why it matters
    remediation: str  # how to fix
    references: list[str] = Field(default_factory=list)
    source: Source = "rule"
    # Optional second opinion from the AI enrichment layer (source="rule" findings
    # keep their deterministic verdict; this is a clearly-separated annotation).
    ai_assessment: str | None = None


class ScanResult(BaseModel):
    """The full result of one scan: findings plus metadata."""

    target: str
    target_type: TargetType
    findings: list[Finding] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    airlock_version: str = __version__
    stats: dict[str, int] = Field(default_factory=dict)
    # Optional human-readable executive summary produced by the AI layer (opt-in).
    ai_summary: str | None = None
    # Count of findings hidden by waivers or a baseline diff (for transparency).
    suppressed: int = 0

    def model_post_init(self, __context: object) -> None:
        """Populate severity counts if not explicitly provided."""
        if not self.stats:
            self.stats = self.compute_stats()

    def compute_stats(self) -> dict[str, int]:
        """Count findings by severity value, including zero buckets."""
        counts: Counter[str] = Counter(f.severity.value for f in self.findings)
        return {sev.value: counts.get(sev.value, 0) for sev in Severity}

    def worst(self) -> Severity:
        """Return the highest severity across findings, or INFO if none."""
        return worst_of([f.severity for f in self.findings])

    def exit_code(self, threshold: Severity) -> int:
        """Return 1 if any finding is at or above ``threshold``, else 0."""
        return 1 if any(f.severity >= threshold for f in self.findings) else 0

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered worst-severity first, then by category then id."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.category, f.id),
        )
