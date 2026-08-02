"""Governance summary + risk register (component → risk → severity → action)."""

from __future__ import annotations

from bulwark_core.findings import Finding

from manifest.bom.model import AIBOM
from manifest.govern.controls import EU_AI_ACT, RMF_FUNCTIONS, assess, assess_eu_ai_act


def risk_register(findings: list[Finding], bom: AIBOM) -> list[dict]:
    """Build a risk register: one row per finding, worst-first, with a component name.

    ``owner`` and ``status`` are emitted as empty template columns. A register without
    them is a list of complaints rather than something a team can track — and Manifest
    cannot infer an owner from a repository, so it supplies the column and leaves the
    value for a human (or a future CODEOWNERS mapping) to fill in.
    """
    rows: list[dict] = []
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        key = f.location.path or ""
        component = bom.get(key)
        rows.append(
            {
                "component": component.name if component else (key or "-"),
                "category": f.category,
                "risk": f.title,
                "severity": f.severity.value,
                "action": f.remediation,
                "owner": "",  # to be assigned
                "status": "open",
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

    eu = assess_eu_ai_act(findings)
    lines += [
        "",
        "## EU AI Act mapping (advisory)",
        "",
        "| Article | Status | Findings | Categories |",
        "| --- | --- | --- | --- |",
    ]
    for article in EU_AI_ACT:
        e = eu[article]
        lines.append(
            f"| {article} | {e['status']} | {e['count']} | {', '.join(e['categories']) or '-'} |"
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
