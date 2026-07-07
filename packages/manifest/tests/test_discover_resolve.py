"""Tests for discoverers, CycloneDX, and resolution."""

from __future__ import annotations

import json
from pathlib import Path

from manifest.bom.cyclonedx import to_cyclonedx
from manifest.bom.model import ComponentType
from manifest.discover import DiscoveryContext, discover_project
from manifest.resolve import licenses, vulns
from manifest.resolve.provenance import find_secrets


def _bom(project: Path):
    ctx = DiscoveryContext.build(project)
    bom = discover_project(project)
    licenses.resolve(bom, ctx)
    return bom, ctx


def test_discovers_component_types(risky_project: Path) -> None:
    bom, _ = _bom(risky_project)
    types = {c.type for c in bom.components}
    assert ComponentType.MODEL in types
    assert ComponentType.DATASET in types
    assert ComponentType.PROMPT in types
    assert {ComponentType.LIBRARY, ComponentType.FRAMEWORK} & types


def test_deps_pinning_and_framework_classification(risky_project: Path) -> None:
    bom, _ = _bom(risky_project)
    pyyaml = next(c for c in bom.components if c.name == "pyyaml")
    assert pyyaml.provenance.pinned and pyyaml.provenance.version == "5.3.1"
    transformers = next(c for c in bom.components if c.name == "transformers")
    assert transformers.type == ComponentType.FRAMEWORK
    assert not transformers.provenance.pinned  # unpinned


def test_model_gets_hash_and_license(clean_project: Path) -> None:
    bom, _ = _bom(clean_project)
    model = next(c for c in bom.components if c.type == ComponentType.MODEL)
    assert model.provenance.hash  # safetensors hashed → pinned
    assert model.license.risk == "ok"  # MIT


def test_license_classification() -> None:
    assert licenses.classify("MIT")[1] == "ok"
    assert licenses.classify("GPL-3.0")[1] == "copyleft"
    assert licenses.classify("cc-by-nc-4.0")[1] == "restricted"
    assert licenses.classify("Weird-1.0")[1] == "unknown"


def test_vuln_seed_lookup(risky_project: Path) -> None:
    bom, _ = _bom(risky_project)
    result = vulns.resolve(bom, offline=True)
    # pyyaml 5.3.1 is in the offline seed (CVE-2020-14343).
    assert any(any("6757" in a.id for a in advs) for advs in result.values())


def test_secret_scan_ignores_placeholders(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text(
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI0K7MDENGbamplekey0001"'
    )
    (tmp_path / "fake.py").write_text('api_key = "YOUR_API_KEY_HERE"')
    ctx = DiscoveryContext.build(tmp_path)
    hits = find_secrets(ctx)
    locs = {loc for loc, _ in hits}
    assert "real.py" in locs
    assert "fake.py" not in locs


def test_cyclonedx_shape(risky_project: Path) -> None:
    bom, _ = _bom(risky_project)
    doc = to_cyclonedx(bom)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    types = {c["type"] for c in doc["components"]}
    assert "machine-learning-model" in types
    # A pinned pypi dep gets a purl.
    purls = [c.get("purl") for c in doc["components"] if c.get("purl")]
    assert any(p.startswith("pkg:pypi/pyyaml@5.3.1") for p in purls)
    # round-trips as JSON
    json.loads(json.dumps(doc))
