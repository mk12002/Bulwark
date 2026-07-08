"""Map findings to the NIST AI RMF functions (Govern/Map/Measure/Manage).

Advisory only (B9) — a transparent, sourced mapping, never a compliance claim.
"""

from __future__ import annotations

from bulwark_core.findings import Finding, Location
from bulwark_core.severity import Severity

RMF_FUNCTIONS = ["GOVERN", "MAP", "MEASURE", "MANAGE"]

# Which RMF function a finding category primarily informs.
_CATEGORY_FUNCTION: dict[str, str] = {
    # Inventory / context → MAP
    "B1": "MAP",
    "B2": "MAP",
    "B6": "MAP",
    "B8": "MAP",
    # License / policy → GOVERN
    "B3": "GOVERN",
    "B9": "GOVERN",
    # Risk identification → MEASURE
    "B4": "MEASURE",
    "B5": "MEASURE",
    "B7": "MEASURE",
}


def _function_for(category: str) -> str:
    if category in _CATEGORY_FUNCTION:
        return _CATEGORY_FUNCTION[category]
    if category.startswith(("M", "P")):  # Airlock component risk
        return "MEASURE"
    if category in ("A3", "A10"):  # Warden response gaps
        return "MANAGE"
    if category.startswith("A"):
        return "MEASURE"
    return "GOVERN"


def assess(findings: list[Finding]) -> dict[str, dict]:
    """Return {function: {"categories": [...], "count": n, "status": "gap"|"ok"}}."""
    out: dict[str, dict] = {
        fn: {"categories": [], "count": 0, "status": "ok"} for fn in RMF_FUNCTIONS
    }
    for f in findings:
        fn = _function_for(f.category)
        entry = out[fn]
        entry["count"] += 1
        if f.category not in entry["categories"]:
            entry["categories"].append(f.category)
        entry["status"] = "gap"
    return out


# --------------------------------------------------------------------------- #
# EU AI Act mapping (advisory; a second control framework alongside NIST AI RMF)
# --------------------------------------------------------------------------- #

# Article/theme → the finding-category prefixes it primarily relates to.
EU_AI_ACT: dict[str, tuple[str, ...]] = {
    "Art.10 Data governance": ("B6", "B1", "B2"),
    "Art.11 Technical documentation": ("B1", "B2", "B8"),
    "Art.12 Record-keeping": ("B8", "B9"),
    "Art.13 Transparency": ("B3",),
    "Art.14 Human oversight": ("A3", "A10", "A4"),
    "Art.15 Accuracy, robustness & cybersecurity": ("B4", "B5", "B7", "M", "P", "A2", "A5", "A8"),
}


def assess_eu_ai_act(findings: list[Finding]) -> dict[str, dict]:
    """Map findings to EU AI Act articles. Advisory — not a conformity assessment."""
    out: dict[str, dict] = {
        art: {"categories": [], "count": 0, "status": "ok"} for art in EU_AI_ACT
    }
    for f in findings:
        for article, prefixes in EU_AI_ACT.items():
            if any(f.category == p or f.category.startswith(p) for p in prefixes):
                entry = out[article]
                entry["count"] += 1
                if f.category not in entry["categories"]:
                    entry["categories"].append(f.category)
                entry["status"] = "gap"
    return out


def b9_findings(assessment: dict[str, dict]) -> list[Finding]:
    """Emit one advisory B9 finding per RMF function that has open gaps."""
    out: list[Finding] = []
    for fn in RMF_FUNCTIONS:
        entry = assessment.get(fn, {})
        if entry.get("status") == "gap":
            cats = ", ".join(entry["categories"])
            out.append(
                Finding(
                    id=f"B9-nist-ai-rmf-{fn.lower()}",
                    category="B9",
                    title=f"NIST AI RMF {fn}: open findings",
                    severity=Severity.LOW,
                    confidence="low",
                    location=Location(target="system", path=f"NIST-AI-RMF:{fn}"),
                    evidence=f"{entry['count']} finding(s) under {fn} ({cats})",
                    rationale=(
                        f"Findings mapped to the NIST AI RMF {fn} function indicate a governance "
                        "gap in that area (advisory mapping, not a compliance determination)."
                    ),
                    remediation=f"Address the {fn}-mapped findings and document the control.",
                    references=["NIST-AI-RMF"],
                    source="analyzer",
                )
            )
    return out
