"""Emit governance signals (B1/B2/B3/B6/B7/B8) from a resolved AIBOM.

B4 (vulns) and B5 (imported Airlock/Warden risk) are produced directly by the
scanner with dynamic severity, not via these rules.
"""

from __future__ import annotations

from bulwark_core.signals import SignalBundle

from manifest.bom.model import AIBOM, Component, ComponentType

_PINNABLE = {
    ComponentType.MODEL,
    ComponentType.DATASET,
    ComponentType.LIBRARY,
    ComponentType.FRAMEWORK,
}


def _has_provenance(c: Component) -> bool:
    p = c.provenance
    return any([p.source, p.author, p.version, p.hash])


def collect(bom: AIBOM, secrets: list[tuple[str, str]]) -> SignalBundle:
    """Return a signal bundle of governance signals for the BOM."""
    bundle = SignalBundle(target="system")

    for c in bom.components:
        # B1 — unpinned pinnable component.
        if c.type in _PINNABLE and not c.provenance.pinned and not c.provenance.hash:
            bundle.add(
                "component.unpinned",
                c.key,
                path=c.key,
                detail=c.type.value,
                evidence=f"{c.type.value} '{c.name}' is used without a pinned version or hash",
            )
        # B2 — no verifiable provenance at all.
        if not _has_provenance(c):
            bundle.add(
                "component.no_provenance",
                c.key,
                path=c.key,
                evidence=f"{c.type.value} '{c.name}' has no source/author/version/hash",
            )
        # B3 — license risk (restricted/copyleft anywhere; unknown for model/dataset).
        risk = c.license.risk
        if risk in ("restricted", "copyleft") or (
            risk == "unknown" and c.type in (ComponentType.MODEL, ComponentType.DATASET)
        ):
            bundle.add(
                "component.license_risk",
                c.key,
                path=c.key,
                detail=risk,
                evidence=f"{c.type.value} '{c.name}' has {risk} license ({c.license.id or 'none'})",
            )
        # B6 — dataset governance gap (no license and no documented external source).
        if (
            c.type == ComponentType.DATASET
            and not c.license.id
            and (c.metadata.get("local_data_file") or not c.provenance.source)
        ):
            bundle.add(
                "dataset.governance_gap",
                c.key,
                path=c.key,
                evidence=f"dataset '{c.name}' has no documented license/source/consent",
            )
        # B8 — inline (unversioned) system prompt.
        if c.type == ComponentType.PROMPT and c.metadata.get("kind") == "system_prompt":
            bundle.add(
                "prompt.unversioned",
                c.key,
                path=c.key,
                evidence=f"system prompt at {c.location} is inline and unversioned",
            )

    # B7 — secret references in the project.
    for location, evidence in secrets:
        bundle.add("project.secret", location, path=location, evidence=evidence)

    return bundle
