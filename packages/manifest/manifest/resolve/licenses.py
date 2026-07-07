"""License detection + risk classification.

Offline and heuristic: detects SPDX-ish license identifiers in LICENSE files and in
``license`` fields of configs, maps each to a risk class, and attaches the nearest
license (by directory) to each component.
"""

from __future__ import annotations

import json
import re

import yaml

from manifest.bom.model import AIBOM, LicenseRisk
from manifest.discover.base import DiscoveryContext

# SPDX id (lowercased fragment) → risk class.
_OK = {
    "mit",
    "apache-2.0",
    "apache",
    "bsd-3-clause",
    "bsd-2-clause",
    "bsd",
    "isc",
    "unlicense",
    "cc0-1.0",
    "mpl-2.0",
}
_COPYLEFT = {"gpl", "gpl-2.0", "gpl-3.0", "agpl", "agpl-3.0", "lgpl"}
_RESTRICTED = {
    "cc-by-nc-4.0",
    "cc-by-nc",
    "cc-by-nc-sa",
    "proprietary",
    "non-commercial",
    "noncommercial",
    "llama2",
    "llama3",
    "openrail",
    "creativeml-openrail-m",
    "research-only",
}

_LICENSE_FIELD = re.compile(r'(?i)"?license"?\s*[:=]\s*"?([A-Za-z0-9.\-_ ]+)')


def classify(identifier: str) -> tuple[str, LicenseRisk]:
    key = identifier.strip().lower()
    for token in _RESTRICTED:
        if token in key:
            return identifier.strip(), "restricted"
    for token in _COPYLEFT:
        if key == token or key.startswith(token):
            return identifier.strip(), "copyleft"
    for token in _OK:
        if key == token or key.startswith(token):
            return identifier.strip(), "ok"
    return identifier.strip(), "unknown"


def _detect_in_text(text: str) -> str | None:
    m = _LICENSE_FIELD.search(text)
    if m:
        return m.group(1)
    head = text[:400].lower()
    for token in list(_RESTRICTED) + list(_COPYLEFT) + list(_OK):
        if token in head:
            return token
    return None


def _dir_licenses(ctx: DiscoveryContext) -> dict[str, str]:
    """Map a directory (relative) → detected license identifier."""
    found: dict[str, str] = {}
    for path in ctx.files:
        name = path.name.lower()
        rel = ctx.rel(path)
        directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
        if name.startswith("license") or name in ("copying",):
            ident = _detect_in_text(ctx.read_text(path))
            if ident:
                found.setdefault(directory, ident)
        elif name in ("config.json", "model_index.json") or name.endswith((".yaml", ".yml")):
            text = ctx.read_text(path)
            try:
                data = yaml.safe_load(text) if not name.endswith(".json") else json.loads(text)
            except (yaml.YAMLError, json.JSONDecodeError):
                data = None
            if isinstance(data, dict) and isinstance(data.get("license"), str):
                found.setdefault(directory, data["license"])
    return found


def resolve(bom: AIBOM, ctx: DiscoveryContext) -> None:
    """Attach a license + risk to each component from the nearest declaration."""
    dir_licenses = _dir_licenses(ctx)
    project_license = dir_licenses.get("")

    for component in bom.components:
        # Dependency licenses need registry (PyPI) metadata, which is online-only;
        # leave them unknown rather than inheriting the project's license.
        if component.type.value in ("library", "framework"):
            continue

        ident: str | None = None
        loc = component.location or ""
        directory = loc.rsplit("/", 1)[0] if "/" in loc else ""
        parts = directory.split("/") if directory else []
        for i in range(len(parts), -1, -1):
            candidate = "/".join(parts[:i])
            if candidate in dir_licenses:
                ident = dir_licenses[candidate]
                break
        ident = ident or project_license
        if ident:
            name, risk = classify(ident)
            component.license.id = name
            component.license.risk = risk
