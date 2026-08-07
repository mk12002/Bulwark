"""SARIF 2.1.0 renderer so GitHub code scanning can ingest Airlock findings.

Emits rich rule descriptors (full description, help text, tags, precision) and
stable ``partialFingerprints`` so code scanning can de-duplicate a finding across
runs even when line numbers or ordering change.
"""

from __future__ import annotations

import hashlib
import json

from bulwark_core import __version__
from bulwark_core.findings import Finding, ScanResult, finding_key
from bulwark_core.severity import Severity
from bulwark_core.taxonomy import category_info, is_known

# SARIF only has: none | note | warning | error.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# SARIF security-severity is a 0.0–10.0 string GitHub uses to rank alerts.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.INFO: "0.0",
    Severity.LOW: "2.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}

_INFO_URI = "https://github.com/mk12002/Bulwark"


def _category_meta(category: str) -> tuple[str, tuple[str, ...]]:
    """Return (description, references) for a taxonomy category, if registered."""
    if not is_known(category):
        return "", ()
    info = category_info(category)
    return info.description, info.references


def _rule_descriptor(category: str, findings: list[Finding]) -> dict:
    sample = findings[0]
    description, refs = _category_meta(category)
    worst = max((f.severity for f in findings), default=Severity.INFO)
    return {
        "id": category,
        "name": category,
        "shortDescription": {"text": sample.title},
        "fullDescription": {"text": description or sample.rationale},
        "helpUri": _INFO_URI,
        "help": {"text": f"{sample.rationale}\n\nRemediation: {sample.remediation}"},
        "defaultConfiguration": {"level": _SARIF_LEVEL[worst]},
        "properties": {
            "tags": ["security", "ai-supply-chain", *refs],
            "security-severity": _SECURITY_SEVERITY[worst],
            "precision": _precision(sample.confidence),
        },
    }


def _precision(confidence: str) -> str:
    # SARIF precision vocabulary: very-high | high | medium | low.
    return {"high": "high", "medium": "medium", "low": "low"}.get(confidence, "medium")


def _fingerprint(f: Finding) -> str:
    """A stable hash of the finding identity for cross-run de-duplication.

    Derived from the canonical :func:`~bulwark_core.findings.finding_key` so the
    SARIF fingerprint, in-scan dedup, and baseline matching can never drift apart —
    a drift here silently resurrects every alert a reviewer had dismissed.
    """
    basis = "|".join(part or "" for part in finding_key(f))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _result(f: Finding) -> dict:
    return {
        "ruleId": f.category,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title}: {f.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.path or f.location.target},
                },
                "logicalLocations": [{"name": f.location.detail or f.id}],
            }
        ],
        "partialFingerprints": {"bulwark/v1": _fingerprint(f)},
        "properties": {
            "ruleInstanceId": f.id,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "rationale": f.rationale,
            "remediation": f.remediation,
            "references": f.references,
            "source": f.source,
            **({"aiAssessment": f.ai_assessment} if f.ai_assessment else {}),
        },
    }


def render_sarif(result: ScanResult) -> str:
    """Serialize a scan result to SARIF 2.1.0 JSON text."""
    by_category: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_category.setdefault(f.category, []).append(f)

    rules = [_rule_descriptor(cat, fs) for cat, fs in sorted(by_category.items())]
    results = [_result(f) for f in result.sorted_findings()]

    driver_name = (result.tool or "bulwark").title()
    run: dict = {
        "tool": {
            "driver": {
                "name": driver_name,
                "informationUri": _INFO_URI,
                "version": result.tool_version or __version__,
                "rules": rules,
            }
        },
        "results": results,
    }
    props: dict = {"targetType": result.target_type, "tool": result.tool}
    if result.ai_summary:
        props["aiSummary"] = result.ai_summary
    if result.suppressed:
        props["suppressedCount"] = result.suppressed
    run["properties"] = props

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }
    return json.dumps(sarif, indent=2)
