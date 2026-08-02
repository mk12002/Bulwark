"""Regression tests for BOM merging, drift tracking, purls, and the Warden bridge.

The Warden bridge previously considered only MCP-server components, so an agent
assembly discovered from a CrewAI crew or an Assistants config was inventoried and
then never audited — the composition claim held only for MCP configs.
"""

from __future__ import annotations

from pathlib import Path

from manifest.bom.cyclonedx import to_cyclonedx
from manifest.bom.diff import diff_boms
from manifest.bom.model import AIBOM, Component, ComponentType, License, Provenance
from manifest.govern.controls import assess
from manifest.resolve.licenses import classify


def _bom(*components: Component) -> AIBOM:
    return AIBOM(project="demo", components=list(components))


# --------------------------------------------------------------------------- #
# Component merging
# --------------------------------------------------------------------------- #


def test_merge_fills_missing_provenance_from_a_later_discoverer() -> None:
    """Two discoverers finding one component is normal; the merge must be additive."""
    bom = _bom(
        Component(
            key="model:hf:org/name",
            type=ComponentType.MODEL,
            name="org/name",
            provenance=Provenance(source="hf:org/name"),
        )
    )
    bom.add(
        Component(
            key="model:hf:org/name",
            type=ComponentType.MODEL,
            name="org/name",
            location="notebooks/explore.ipynb#cell3",
            provenance=Provenance(source="hf:org/name", author="org", version="abc123"),
        )
    )
    merged = bom.get("model:hf:org/name")
    assert merged is not None
    assert merged.provenance.author == "org"
    assert merged.provenance.version == "abc123"
    assert merged.location == "notebooks/explore.ipynb#cell3"
    assert len(bom.components) == 1


def test_merge_prefers_a_concrete_license_over_unknown() -> None:
    bom = _bom(
        Component(key="k", type=ComponentType.MODEL, name="m", license=License(risk="unknown"))
    )
    bom.add(
        Component(
            key="k",
            type=ComponentType.MODEL,
            name="m",
            license=License(id="Apache-2.0", risk="ok"),
        )
    )
    merged = bom.get("k")
    assert merged is not None and merged.license.id == "Apache-2.0" and merged.license.risk == "ok"


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #


def test_diff_detects_a_publisher_change_under_the_same_name() -> None:
    """A model switching organisation is the most security-relevant provenance change."""
    old = _bom(
        Component(
            key="model:hf:trusted/name",
            type=ComponentType.MODEL,
            name="name",
            provenance=Provenance(source="hf:trusted/name", author="trusted"),
        )
    )
    new = _bom(
        Component(
            key="model:hf:trusted/name",
            type=ComponentType.MODEL,
            name="name",
            provenance=Provenance(source="hf:someone-else/name", author="someone-else"),
        )
    )
    diff = diff_boms(old, new)
    assert diff.has_changes
    assert len(diff.changed) == 1


def test_diff_reports_a_version_bump_as_changed_not_add_remove() -> None:
    old = _bom(
        Component(
            key="pypi:requests@2.31.0",
            type=ComponentType.LIBRARY,
            name="requests",
            provenance=Provenance(source="pypi", version="2.31.0"),
        )
    )
    new = _bom(
        Component(
            key="pypi:requests@2.32.0",
            type=ComponentType.LIBRARY,
            name="requests",
            provenance=Provenance(source="pypi", version="2.32.0"),
        )
    )
    diff = diff_boms(old, new)
    assert len(diff.changed) == 1
    assert not diff.added and not diff.removed


# --------------------------------------------------------------------------- #
# purl
# --------------------------------------------------------------------------- #


def test_models_get_a_huggingface_purl() -> None:
    """Without a purl a model is not identifiable across tools or advisory feeds."""
    bom = _bom(
        Component(
            key="model:hf:org/name",
            type=ComponentType.MODEL,
            name="org/name",
            provenance=Provenance(source="hf:org/name", version="abc123"),
        )
    )
    component = to_cyclonedx(bom)["components"][0]
    assert component["purl"] == "pkg:huggingface/org/name@abc123"
    assert component["type"] == "machine-learning-model"


def test_pypi_purl_is_unchanged() -> None:
    bom = _bom(
        Component(
            key="pypi:requests@2.31.0",
            type=ComponentType.LIBRARY,
            name="requests",
            provenance=Provenance(source="pypi", version="2.31.0"),
        )
    )
    assert to_cyclonedx(bom)["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"


# --------------------------------------------------------------------------- #
# Licence classification
# --------------------------------------------------------------------------- #


def test_agpl_is_distinguished_from_ordinary_copyleft() -> None:
    """Network copyleft is the highest-consequence term for a hosted product."""
    assert classify("AGPL-3.0")[1] == "restricted"
    assert classify("GPL-3.0")[1] == "copyleft"
    assert classify("MIT")[1] == "ok"
    assert classify("llama3-community")[1] == "restricted"


# --------------------------------------------------------------------------- #
# Governance status is three-state
# --------------------------------------------------------------------------- #


def test_a_single_low_finding_is_advisory_not_a_gap() -> None:
    from bulwark_core.findings import Finding, Location
    from bulwark_core.severity import Severity

    low = Finding(
        id="B8-x",
        category="B8",
        title="t",
        severity=Severity.LOW,
        confidence="low",
        location=Location(target="system", path="p"),
        evidence="e",
        rationale="r",
        remediation="fix",
    )
    high = low.model_copy(update={"id": "B7-x", "category": "B7", "severity": Severity.HIGH})

    assert assess([low])["MAP"]["status"] == "advisory"
    assert assess([high])["MEASURE"]["status"] == "gap"
    assert assess([])["GOVERN"]["status"] == "ok"


# --------------------------------------------------------------------------- #
# The Warden bridge must see agent assemblies, not only MCP configs
# --------------------------------------------------------------------------- #


def test_warden_bridge_audits_a_discovered_agent_component(tmp_path: Path) -> None:
    """A CrewAI/Assistants assembly with no .mcp.json was previously never audited."""
    from manifest.risk import bridge_risk

    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "name: risky-agent\n"
        "autonomy: autonomous\n"
        "tools:\n"
        "  - name: get_secret\n"
        "    description: Read a credential from the vault\n"
        "  - name: post_webhook\n"
        "    description: POST data to a URL\n"
        "  - name: browse_web\n"
        "    description: Visit a URL and return the page\n",
        encoding="utf-8",
    )
    bom = _bom(
        Component(
            key="agent:agent.yaml",
            type=ComponentType.AGENT,
            name="risky-agent",
            location="agent.yaml",
        )
    )
    findings = bridge_risk(bom, tmp_path, offline=True)
    categories = {f.category for f in findings}
    assert categories, "the agent assembly produced no Warden findings"
    assert any(c.startswith("A") for c in categories), f"expected A-codes, got {categories}"
