"""Map an AIBOM to CycloneDX 1.5 JSON with ML/AI component types.

Rides the standard so existing SBOM tooling can consume the output. Findings are
attached as component properties (namespaced ``bulwark:*``).
"""

from __future__ import annotations

import hashlib
import json

from bulwark_core import __version__ as _core_version

from manifest.bom.model import AIBOM, Component, ComponentType

# AIBOM component type → CycloneDX component type.
_CDX_TYPE: dict[ComponentType, str] = {
    ComponentType.MODEL: "machine-learning-model",
    ComponentType.DATASET: "data",
    ComponentType.LIBRARY: "library",
    ComponentType.FRAMEWORK: "framework",
    ComponentType.MCP_SERVER: "application",
    ComponentType.TOOL: "application",
    ComponentType.PROMPT: "data",
    ComponentType.AGENT: "application",
}

_PURL_ECOSYSTEM = {"pypi": "pypi", "npm": "npm"}
# Hugging Face repos have a registered purl type, so models and datasets can be
# identified across tools and matched by advisory feeds the same way packages are.
_HF_PREFIXES = {"hf:": "huggingface", "hf-dataset:": "huggingface"}


def _serial(bom: AIBOM) -> str:
    basis = f"{bom.project}:{bom.generated_at.isoformat()}".encode()
    digest = hashlib.sha256(basis).hexdigest()
    return f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _purl(component: Component) -> str | None:
    """A package URL for the component, when its ecosystem is identifiable.

    purl is what makes a component comparable *across* tools — two scanners emitting
    ``pkg:pypi/requests@2.31.0`` are talking about the same thing with no negotiation,
    and advisory databases key on it. Models get ``pkg:huggingface/org/name@revision``
    so a BOM consumer can identify them too, not only libraries.
    """
    src = component.provenance.source or ""
    ver = component.provenance.version
    for prefix, eco in _PURL_ECOSYSTEM.items():
        if src == prefix:
            return f"pkg:{eco}/{component.name}" + (f"@{ver}" if ver else "")
    for prefix, eco in _HF_PREFIXES.items():
        if src.startswith(prefix):
            repo = src[len(prefix) :].strip("/")
            if not repo:
                return None
            # The revision, when pinned, is the immutable identifier worth carrying.
            rev = ver or component.provenance.hash
            return f"pkg:{eco}/{repo}" + (f"@{rev}" if rev else "")
    return None


def _licenses(component: Component) -> list[dict]:
    lic = component.license
    if lic.id:
        return [{"license": {"id": lic.id}}]
    if lic.name:
        return [{"license": {"name": lic.name}}]
    return []


def _properties(component: Component) -> list[dict]:
    props: list[dict] = [{"name": "bulwark:type", "value": component.type.value}]
    if component.location:
        props.append({"name": "bulwark:location", "value": component.location})
    if component.provenance.source:
        props.append({"name": "bulwark:source", "value": component.provenance.source})
    props.append({"name": "bulwark:pinned", "value": str(component.provenance.pinned).lower()})
    props.append({"name": "bulwark:license-risk", "value": component.license.risk})
    # Agent components carry assembly detail (aligned with the emerging CycloneDX Agent BOM):
    # autonomy, model, and the tools wired in — so a BOM reflects assemblies, not just parts.
    if component.type is ComponentType.AGENT:
        meta = component.metadata
        if meta.get("framework"):
            props.append({"name": "bulwark:agent:framework", "value": str(meta["framework"])})
        if meta.get("autonomy"):
            props.append({"name": "bulwark:agent:autonomy", "value": str(meta["autonomy"])})
        if meta.get("model"):
            props.append({"name": "bulwark:agent:model", "value": str(meta["model"])})
        props.append({"name": "bulwark:agent:tool-count", "value": str(meta.get("tool_count", 0))})
        for tool_name in meta.get("tools", []) or []:
            props.append({"name": "bulwark:agent:tool", "value": str(tool_name)})
    for fid in component.findings:
        props.append({"name": "bulwark:finding", "value": fid})
    return props


def _cdx_component(component: Component) -> dict:
    entry: dict = {
        "type": _CDX_TYPE.get(component.type, "application"),
        "bom-ref": component.key,
        "name": component.name,
        "properties": _properties(component),
    }
    if component.provenance.version:
        entry["version"] = component.provenance.version
    if component.provenance.author:
        entry["author"] = component.provenance.author
    if component.provenance.hash:
        entry["hashes"] = [{"alg": "SHA-256", "content": component.provenance.hash}]
    purl = _purl(component)
    if purl:
        entry["purl"] = purl
    licenses = _licenses(component)
    if licenses:
        entry["licenses"] = licenses
    return entry


def to_cyclonedx(bom: AIBOM) -> dict:
    """Build the CycloneDX document as a dict."""
    deps: dict[str, set[str]] = {}
    for rel in bom.relationships:
        deps.setdefault(rel.src, set()).add(rel.dst)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": _serial(bom),
        "version": 1,
        "metadata": {
            "timestamp": bom.generated_at.isoformat(),
            "tools": [{"vendor": "Bulwark", "name": "Manifest", "version": _core_version}],
            "component": {"type": "application", "name": bom.project, "bom-ref": bom.project},
        },
        "components": [_cdx_component(c) for c in bom.components],
        "dependencies": [
            {"ref": src, "dependsOn": sorted(dsts)} for src, dsts in sorted(deps.items())
        ],
    }


def render_cyclonedx(bom: AIBOM) -> str:
    """Serialize the AIBOM to CycloneDX JSON text (ASCII-safe)."""
    return json.dumps(to_cyclonedx(bom), indent=2, ensure_ascii=True)
