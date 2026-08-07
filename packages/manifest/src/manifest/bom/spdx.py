"""Map an AIBOM to SPDX 2.3 JSON (an alternative to CycloneDX).

Some governance/compliance toolchains standardize on SPDX; Manifest emits both so
the AI-BOM drops into whichever pipeline the consumer already runs.
"""

from __future__ import annotations

import hashlib
import json
import re

from bulwark_core import __version__ as _core_version

from manifest.bom.model import AIBOM, Component

_NOASSERTION = "NOASSERTION"
_SPDXID_BAD = re.compile(r"[^A-Za-z0-9.\-]+")

# SPDX defines ~40 typed relationships where CycloneDX 1.5 has only "dependsOn", so
# the AIBOM's own relationship verbs survive translation here instead of being
# flattened. Anything unmapped degrades to DEPENDS_ON, which is always true.
_RELATIONSHIP_TYPE: dict[str, str] = {
    "uses": "DEPENDS_ON",
    "wires": "DEPENDS_ON",
    "trained-on": "GENERATED_FROM",
    "generated-from": "GENERATED_FROM",
    "contains": "CONTAINS",
    "variant-of": "VARIANT_OF",
    "describes": "DESCRIBES",
    "documented-by": "DOCUMENTATION_OF",
}


def _spdxid(key: str) -> str:
    return "SPDXRef-" + _SPDXID_BAD.sub("-", key).strip("-")


def _download_location(component: Component) -> str:
    src = component.provenance.source or ""
    ver = component.provenance.version
    if src == "pypi":
        return f"pip+{component.name}" + (f"=={ver}" if ver else "")
    if src == "npm":
        return f"npm+{component.name}" + (f"@{ver}" if ver else "")
    if src.startswith(("hf:", "hf-dataset:")):
        return f"https://huggingface.co/{src.split(':', 1)[1]}"
    return _NOASSERTION


def _package(component: Component) -> dict:
    pkg: dict = {
        "SPDXID": _spdxid(component.key),
        "name": component.name,
        "versionInfo": component.provenance.version or _NOASSERTION,
        "downloadLocation": _download_location(component),
        "filesAnalyzed": False,
        "licenseConcluded": component.license.id or _NOASSERTION,
        "licenseDeclared": component.license.id or _NOASSERTION,
        "copyrightText": _NOASSERTION,
    }
    if component.provenance.author:
        pkg["originator"] = f"Organization: {component.provenance.author}"
    if component.provenance.hash:
        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": component.provenance.hash}]
    pkg["comment"] = f"bulwark-type={component.type.value}; findings={','.join(component.findings)}"
    return pkg


def to_spdx(bom: AIBOM) -> dict:
    ns_hash = hashlib.sha256(f"{bom.project}{bom.generated_at.isoformat()}".encode()).hexdigest()[
        :16
    ]
    doc: dict = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": bom.project,
        "documentNamespace": f"https://bulwark.local/spdx/{bom.project}-{ns_hash}",
        "creationInfo": {
            "created": bom.generated_at.isoformat(),
            "creators": [f"Tool: Manifest-{_core_version}", "Organization: Bulwark"],
        },
        "packages": [_package(c) for c in bom.components],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": _spdxid(c.key),
            }
            for c in bom.components
        ],
    }
    for rel in bom.relationships:
        doc["relationships"].append(
            {
                "spdxElementId": _spdxid(rel.src),
                "relationshipType": _RELATIONSHIP_TYPE.get(rel.rel.lower(), "DEPENDS_ON"),
                "relatedSpdxElement": _spdxid(rel.dst),
            }
        )
    return doc


def render_spdx(bom: AIBOM) -> str:
    return json.dumps(to_spdx(bom), indent=2, ensure_ascii=True)
