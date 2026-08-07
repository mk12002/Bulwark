#!/usr/bin/env python
"""Inventory an AI project and emit a standards-based AI-BOM.

    python examples/03_generate_an_ai_bom.py [PROJECT_DIR]

Manifest discovers models, datasets, MCP servers, prompts, tools, dependencies,
notebooks, and agent assemblies by static parsing — it never runs the project. With
``scan_risk=True`` it also calls Airlock and Warden as libraries and folds their
findings into the same document, which is what makes the BOM a governance artifact
rather than a list.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from manifest.bom.cyclonedx import to_cyclonedx
from manifest.bom.model import AIBOM
from manifest.rules import RuleEngine, load_rules
from manifest.scanner import ManifestScanner

DEFAULT_PROJECT = "packages/manifest/fixtures/sample_project_risky"


def main(project: str = DEFAULT_PROJECT) -> int:
    scanner = ManifestScanner(
        RuleEngine(load_rules()),
        offline=True,  # no network: OSV uses the bundled advisory seed
        scan_risk=True,  # fold in Airlock (parts) + Warden (assemblies)
        govern=True,  # add NIST AI RMF + EU AI Act mapping and a risk register
    )
    result = scanner.scan(project)
    bom = AIBOM.model_validate(result.meta["aibom"])

    print(f"project    : {bom.project}")
    print(f"components : {len(bom.components)}  {bom.type_counts()}")
    print(f"findings   : {len(result.findings)}\n")

    print("Unpinned components (B1 — not reproducible, publisher can move them):")
    for c in bom.components:
        if not c.provenance.pinned:
            print(f"  - {c.type.value:12} {c.name[:48]}")

    print("\nGovernance control status:")
    for fn, entry in result.meta["governance"]["nist_ai_rmf"].items():
        print(f"  NIST {fn:8} {entry['status']:9} ({entry['count']} finding(s))")

    print("\nRisk register (worst first):")
    for row in result.meta["risk_register"][:5]:
        print(f"  {row['severity']:8} {row['category']:3} {row['component'][:34]:34} {row['risk'][:36]}")

    cyclonedx = to_cyclonedx(bom)
    print(f"\nCycloneDX {cyclonedx['specVersion']}: {len(cyclonedx['components'])} components")
    with open("bom.json", "w", encoding="utf-8") as fh:
        json.dump(cyclonedx, fh, indent=2)
    print("wrote bom.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
