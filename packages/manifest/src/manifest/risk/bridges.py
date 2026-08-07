"""Compose Airlock (parts) and Warden (assembly) as risk backends.

Under ``--scan-risk`` Manifest calls the sibling tools as libraries, rewrites each
imported finding to point at the owning BOM component, and adds a B5 roll-up per
component that carries HIGH+ imported risk. Degrades gracefully if a tool is not
installed or a scan errors.
"""

from __future__ import annotations

from pathlib import Path

from bulwark_core.findings import Finding, Location
from bulwark_core.severity import Severity

from manifest.bom.model import AIBOM, Component, ComponentType


def _b5(component: Component, worst: Severity, source_tool: str, n: int) -> Finding:
    return Finding(
        id=f"B5-{component.key}",
        category="B5",
        title=f"High-risk component flagged by {source_tool}",
        severity=worst,
        confidence="high",
        location=Location(target="system", path=component.key),
        evidence=f"{n} {source_tool} finding(s) on '{component.name}' (worst: {worst.value})",
        rationale="A discovered component carries risk from a dedicated Bulwark scanner.",
        remediation=f"Review the inline {source_tool} findings on this component.",
        references=["OWASP:LLM03:2025", "OWASP:LLM06:2025"],
        source="analyzer",
    )


def _rehome(findings: list[Finding], component_key: str) -> list[Finding]:
    """Point each imported finding at the owning component (so it attaches)."""
    out: list[Finding] = []
    for f in findings:
        out.append(
            f.model_copy(update={"location": f.location.model_copy(update={"path": component_key})})
        )
    return out


def _airlock_on_models(bom: AIBOM, root: Path, offline: bool) -> list[Finding]:
    try:
        from airlock.rules import RuleEngine, load_rules
        from airlock.scanners.model import ModelScanner
    except ImportError:
        return []
    scanner = ModelScanner(RuleEngine(load_rules()))
    findings: list[Finding] = []
    for c in bom.by_type(ComponentType.MODEL):
        target: str | None = None
        if c.metadata.get("local_weight_file") and c.location:
            target = str(root / c.location)
        elif c.metadata.get("hf_repo") and not offline:
            target = f"hf:{c.metadata['hf_repo']}"
        if not target:
            continue
        try:
            result = scanner.scan(target)
        except Exception:
            continue
        real = [f for f in result.findings if f.source != "analyzer"]
        if real:
            findings += _rehome(real, c.key)
            worst = max((f.severity for f in real), default=Severity.INFO)
            if worst >= Severity.HIGH:
                findings.append(_b5(c, worst, "Airlock", len(real)))
    return findings


def _warden_on_assemblies(bom: AIBOM, root: Path) -> list[Finding]:
    try:
        from warden.importers import ImportError_, import_agent
        from warden.rules import RuleEngine as WEngine
        from warden.rules import load_rules as w_load_rules
        from warden.scanner import WardenScanner
    except ImportError:
        return []
    # An assembly is any MCP client config *or* any discovered agent config
    # (agent manifest / OpenAI Assistants / CrewAI). Both carry a location that an
    # importer can parse; missing AGENT components here would silently skip Warden
    # analysis for every non-MCP framework.
    candidates = [
        c
        for c in bom.components
        if c.type in (ComponentType.MCP_SERVER, ComponentType.AGENT) and c.location
    ]
    locations = sorted({c.location for c in candidates if c.location})
    if not locations:
        return []
    scanner = WardenScanner(WEngine(w_load_rules()))
    findings: list[Finding] = []
    for loc in locations:
        try:
            _spec, _imp = import_agent(root / loc)
        except ImportError_:
            continue
        result = scanner.scan(str(root / loc))
        real = [f for f in result.findings if f.source != "analyzer"]
        if real:
            key = f"assembly:{loc}"
            findings += _rehome(real, key)
            worst = max((f.severity for f in real), default=Severity.INFO)
            if worst >= Severity.HIGH:
                # Synthesize a component so the assembly risk has a home in the BOM.
                bom.add(
                    Component(
                        key=key,
                        type=ComponentType.AGENT,
                        name=loc,
                        location=loc,
                        metadata={"assembly": True},
                    )
                )
                findings.append(
                    _b5(bom.get(key), worst, "Warden", len(real))  # type: ignore[arg-type]
                )
    return findings


def bridge_risk(bom: AIBOM, root: Path, offline: bool = True) -> list[Finding]:
    """Run the Airlock + Warden bridges and return their findings (M/P/A + B5)."""
    return _airlock_on_models(bom, root, offline) + _warden_on_assemblies(bom, root)
