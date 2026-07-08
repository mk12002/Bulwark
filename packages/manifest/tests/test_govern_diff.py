"""Tests for EU AI Act mapping and AI-BOM diff."""

from __future__ import annotations

from datetime import UTC, datetime

from bulwark_core.findings import Finding, Location
from bulwark_core.severity import Severity
from manifest.bom.diff import diff_boms
from manifest.bom.model import AIBOM, Component, ComponentType, License, Provenance
from manifest.govern import assess_eu_ai_act


def _f(cat: str) -> Finding:
    return Finding(
        id=f"{cat}-x",
        category=cat,
        title="t",
        severity=Severity.HIGH,
        confidence="high",
        location=Location(target="system"),
        evidence="e",
        rationale="r",
        remediation="fix",
    )


def test_eu_ai_act_maps_categories() -> None:
    a = assess_eu_ai_act([_f("B4"), _f("B6"), _f("A3")])
    assert a["Art.15 Accuracy, robustness & cybersecurity"]["status"] == "gap"  # B4
    assert a["Art.10 Data governance"]["status"] == "gap"  # B6
    assert a["Art.14 Human oversight"]["status"] == "gap"  # A3
    # An unaffected article stays ok.
    assert a["Art.13 Transparency"]["status"] == "ok"


def test_eu_ai_act_maps_imported_model_findings() -> None:
    a = assess_eu_ai_act([_f("M1")])  # Airlock model risk → cybersecurity
    assert a["Art.15 Accuracy, robustness & cybersecurity"]["status"] == "gap"


# --------------------------------------------------------------------------- #
# BOM diff
# --------------------------------------------------------------------------- #


def _comp(key: str, ctype: ComponentType, name: str, version: str | None = None) -> Component:
    return Component(
        key=key, type=ctype, name=name, provenance=Provenance(version=version, source="pypi")
    )


def _bom(components: list[Component]) -> AIBOM:
    return AIBOM(project="p", generated_at=datetime.now(UTC), components=components)


def test_diff_added_and_removed() -> None:
    old = _bom([_comp("pypi:a@1", ComponentType.LIBRARY, "a", "1")])
    new = _bom([_comp("pypi:b@1", ComponentType.LIBRARY, "b", "1")])
    d = diff_boms(old, new)
    assert {c.name for c in d.added} == {"b"}
    assert {c.name for c in d.removed} == {"a"}
    assert d.has_changes


def test_diff_version_change_is_changed_not_add_remove() -> None:
    old = _bom([_comp("pypi:torch@2.3.0", ComponentType.FRAMEWORK, "torch", "2.3.0")])
    new = _bom([_comp("pypi:torch@2.4.0", ComponentType.FRAMEWORK, "torch", "2.4.0")])
    d = diff_boms(old, new)
    assert d.added == [] and d.removed == []
    assert len(d.changed) == 1
    old_c, new_c = d.changed[0]
    assert old_c.provenance.version == "2.3.0" and new_c.provenance.version == "2.4.0"


def test_diff_license_change_shown() -> None:
    old = _bom([_comp("model:m@1", ComponentType.MODEL, "m", "1")])
    old.components[0].license = License(id="mit", risk="ok")
    new = _bom([_comp("model:m@1", ComponentType.MODEL, "m", "1")])
    new.components[0].license = License(id="cc-by-nc-4.0", risk="restricted")
    d = diff_boms(old, new)
    # same key → no add/remove; license change rendered
    assert "restricted" in d.render() or "cc-by-nc" in d.render()


def test_no_changes_when_identical() -> None:
    b = _bom([_comp("pypi:a@1", ComponentType.LIBRARY, "a", "1")])
    assert not diff_boms(b, b).has_changes
