"""Empirical study harness: scan a corpus and aggregate reproducible statistics.

This is the engine behind the "we scanned N public artifacts and X% had at least
one over-permissioned tool" write-up. It runs a list of targets through the scan
pipeline and produces category/severity histograms, prevalence rates, and
reproducibility metadata (Airlock version, rule count, timestamp) so the numbers
are defensible.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from bulwark_core import __version__
from bulwark_core.findings import ScanResult
from bulwark_core.severity import Severity


@dataclass
class CorpusItem:
    """One entry to scan: a kind (model|mcp|toolspec) and a target string."""

    kind: str
    target: str


@dataclass
class StudyReport:
    """Aggregate results over a corpus."""

    total: int = 0
    scanned: int = 0
    errored: int = 0
    with_findings: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    per_target: list[dict[str, object]] = field(default_factory=list)
    tool_version: str = __version__
    rule_count: int = 0
    generated_at: str = ""

    @property
    def prevalence(self) -> float:
        """Fraction of scanned targets with at least one finding."""
        return (self.with_findings / self.scanned) if self.scanned else 0.0


ScanFn = Callable[[str, str], ScanResult]


def run_study(items: list[CorpusItem], scan_fn: ScanFn, *, rule_count: int = 0) -> StudyReport:
    """Scan every corpus item and aggregate. ``scan_fn(kind, target)`` is injected."""
    report = StudyReport(
        total=len(items),
        rule_count=rule_count,
        generated_at=datetime.now(UTC).isoformat(),
    )
    cat: Counter[str] = Counter()
    sev: Counter[str] = Counter()
    rule: Counter[str] = Counter()

    for item in items:
        try:
            result = scan_fn(item.kind, item.target)
        except Exception as exc:
            report.errored += 1
            report.per_target.append(
                {"kind": item.kind, "target": item.target, "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        report.scanned += 1
        findings = result.findings
        if findings:
            report.with_findings += 1
        for f in findings:
            cat[f.category] += 1
            sev[f.severity.value] += 1
            rule[f.id] += 1
        report.per_target.append(
            {
                "kind": item.kind,
                "target": item.target,
                "findings": len(findings),
                "worst": result.worst().value if findings else "none",
                "categories": sorted({f.category for f in findings}),
            }
        )

    report.by_category = dict(sorted(cat.items()))
    report.by_severity = {s.value: sev.get(s.value, 0) for s in Severity}
    report.top_rules = rule.most_common(15)
    return report


def render_markdown(report: StudyReport) -> str:
    """Render a study report as a shareable Markdown document."""
    lines = [
        "# Bulwark corpus scan",
        "",
        f"- Airlock version: `{report.tool_version}` -- rules: {report.rule_count}",
        f"- Generated: {report.generated_at}",
        f"- Targets: {report.total} ({report.scanned} scanned, {report.errored} errored)",
        f"- **Prevalence: {report.prevalence:.0%}** of scanned targets had >=1 finding",
        "",
        "## Findings by category",
        "",
        "| Category | Count |",
        "| --- | --- |",
    ]
    lines += [f"| {c} | {n} |" for c, n in report.by_category.items()] or ["| (none) | 0 |"]
    lines += ["", "## Findings by severity", "", "| Severity | Count |", "| --- | --- |"]
    lines += [f"| {s} | {n} |" for s, n in report.by_severity.items() if n]
    lines += ["", "## Top rules", "", "| Rule | Hits |", "| --- | --- |"]
    lines += [f"| {rid} | {n} |" for rid, n in report.top_rules] or ["| (none) | 0 |"]
    return "\n".join(lines) + "\n"
