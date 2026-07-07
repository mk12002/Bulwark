"""Governance summary + risk register (component → risk → severity → action)."""

from __future__ import annotations

from bulwark_core.findings import Finding

from manifest.bom.model import AIBOM
from manifest.govern.controls import RMF_FUNCTIONS, assess


def risk_register(findings: list[Finding], bom: AIBOM) -> list[dict]:
    """Build a risk register: one row per finding, worst-first, with a component name."""
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    rows: list[dict] = []
    for f in sorted(findings, key=lambda x: -rank[x.severity.value]):
        key = f.location.path or ""
        component = bom.get(key)
        rows.append(
            {
                "component": component.name if component else (key or "-"),
                "category": f.category,
                "risk": f.title,
                "severity": f.severity.value,
                "action": f.remediation,
            }
        )
    return rows


def render_governance_md(findings: list[Finding], bom: AIBOM) -> str:
    """Render a Markdown governance summary + risk register."""
    a = assess(findings)
    lines = [
        f"# Governance report — {bom.project}",
        "",
        f"- Components: {len(bom.components)}  ({_counts(bom)})",
        f"- Findings: {len(findings)}",
        "",
        "## NIST AI RMF coverage (advisory)",
        "",
        "| Function | Status | Findings | Categories |",
        "| --- | --- | --- | --- |",
    ]
    for fn in RMF_FUNCTIONS:
        e = a[fn]
        lines.append(
            f"| {fn} | {e['status']} | {e['count']} | {', '.join(e['categories']) or '-'} |"
        )

    lines += [
        "",
        "## Risk register",
        "",
        "| Component | Cat | Severity | Risk | Action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in risk_register(findings, bom):
        lines.append(
            f"| {row['component']} | {row['category']} | {row['severity']} | "
            f"{row['risk']} | {row['action']} |"
        )
    return "\n".join(lines) + "\n"


def _counts(bom: AIBOM) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(bom.type_counts().items()))
