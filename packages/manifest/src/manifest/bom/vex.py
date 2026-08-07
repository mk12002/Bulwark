"""VEX (Vulnerability Exploitability eXchange) output, CycloneDX 1.5 flavor.

A VEX document answers, per vulnerability, *is this product actually affected?* Manifest
seeds it from the known-vulnerable-dependency findings (B4) it detected — each becomes a
``vulnerabilities[]`` entry marked **exploitable** (the vulnerable version is present),
with the affected component reference, the advisory id/source, a severity rating, and an
``analysis`` block. A reviewer can then flip any entry to ``not_affected`` with a
justification — the whole point of VEX — without re-running a scan.
"""

from __future__ import annotations

import json

from bulwark_core import __version__ as _core_version
from bulwark_core.findings import Finding, ScanResult
from bulwark_core.severity import Severity

# CycloneDX vulnerability rating severity strings.
_CDX_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def _advisory_id(finding: Finding) -> str:
    """The advisory identifier (GHSA/CVE) — from references, falling back to the id."""
    for ref in finding.references:
        if ref and ref != "OSV":
            return ref
    return finding.id


def _vulnerability(finding: Finding) -> dict:
    ref = finding.location.path or finding.location.target or "unknown-component"
    return {
        "bom-ref": finding.id,
        "id": _advisory_id(finding),
        "source": {"name": "OSV", "url": "https://osv.dev"},
        "ratings": [
            {
                "severity": _CDX_SEVERITY.get(finding.severity, "unknown"),
                "method": "other",
            }
        ],
        "description": finding.evidence or finding.title,
        "recommendation": finding.remediation,
        "affects": [{"ref": ref}],
        "analysis": {
            "state": "exploitable",
            "detail": (
                "Detected by Manifest: the vulnerable version is present in the project. "
                "Set to not_affected with a justification if analysis shows otherwise."
            ),
        },
    }


def to_vex(result: ScanResult) -> dict:
    """Build a CycloneDX 1.5 VEX document from a Manifest scan result (B4 findings)."""
    vulns = [_vulnerability(f) for f in result.findings if f.category == "B4"]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "Bulwark", "name": "Manifest", "version": _core_version}],
            "component": {"type": "application", "name": result.target, "bom-ref": result.target},
        },
        "vulnerabilities": vulns,
    }


def render_vex(result: ScanResult) -> str:
    """Serialize the VEX document to JSON text (ASCII-safe)."""
    return json.dumps(to_vex(result), indent=2, ensure_ascii=True)
