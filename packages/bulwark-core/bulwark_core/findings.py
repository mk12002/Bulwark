"""Core pydantic data model: Location, Finding, and ScanResult.

These are the stable, machine-readable shapes every Bulwark tool produces and every
reporter consumes. Severity lives in :mod:`bulwark_core.severity`.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from bulwark_core import __version__
from bulwark_core.severity import Severity, worst_of

Confidence = Literal["low", "medium", "high"]
Source = Literal["rule", "analyzer", "ai"]
# Free-form so each tool names its own domain: "model"/"mcp" (Airlock), "agent"
# (Warden), "system" (Manifest).
TargetType = str


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
    tool: str = "bulwark"  # which Bulwark tool produced this (airlock|warden|manifest)
    findings: list[Finding] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_version: str = __version__
    stats: dict[str, int] = Field(default_factory=dict)
    # Optional human-readable executive summary produced by the AI layer (opt-in).
    ai_summary: str | None = None
    # Count of findings hidden by waivers or a baseline diff (for transparency).
    suppressed: int = 0
    # Optional 0–100 headline score (e.g. Warden's agency score); shown in headers.
    score: int | None = None
    # Tool-specific structured metadata (e.g. the normalized AgentSpec).
    meta: dict = Field(default_factory=dict)

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


# --------------------------------------------------------------------------- #
# Finding identity
# --------------------------------------------------------------------------- #

FindingKey = tuple[str, str | None, str | None, str]


def finding_key(f: Finding) -> FindingKey:
    """The canonical identity of a finding: rule id + location + evidence.

    **This is the single definition of "the same finding"** and three subsystems
    depend on it meaning one thing:

    - :func:`dedupe` — collapsing duplicate findings within one scan;
    - :mod:`bulwark_core.postprocess` — matching a stored baseline, so a
      regression-only scan reports only what is new;
    - :mod:`bulwark_core.report.sarif` — ``partialFingerprints``, which is how code
      scanning recognises an alert across runs and keeps it dismissed.

    Changing this tuple therefore invalidates every existing baseline file *and*
    resurrects every dismissed code-scanning alert — two silent consequences. Keep
    it here, and keep it stable.

    Severity and rationale are deliberately excluded: both are derived from the rule,
    so including them would add nothing and couple identity to wording.
    """
    return (f.id, f.location.path, f.location.detail, f.evidence)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop findings with an identical :func:`finding_key`, preserving order.

    Needed because analyzers can legitimately double-report: the format-confusion
    analyzer re-runs the pickle disassembler on a file whose extension lies, so a
    payload is discovered twice by design.
    """
    seen: set[FindingKey] = set()
    unique: list[Finding] = []
    for f in findings:
        key = finding_key(f)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
