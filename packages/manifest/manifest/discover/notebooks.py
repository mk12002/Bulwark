"""Notebook discovery: parse .ipynb cells for models, datasets, and pip installs."""

from __future__ import annotations

import json
import re

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register

_HF_REF = re.compile(r"""(?:from_pretrained|hf_hub_download)\s*\(\s*["']([\w\-./]+/[\w\-.]+)["']""")
_LOAD_DATASET = re.compile(r"""load_dataset\s*\(\s*["']([\w\-./]+)["']""")
_PIP = re.compile(r"""^\s*[!%]\s*pip\s+install\s+(.+)$""", re.MULTILINE)
_PKG = re.compile(r"^([A-Za-z0-9_.\-]+)(?:[=<>~!]=?([A-Za-z0-9_.\-]+))?")


def _cell_source(cell: dict) -> str:
    src = cell.get("source", "")
    return "".join(src) if isinstance(src, list) else str(src)


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []
    for path in ctx.by_suffix(".ipynb"):
        try:
            nb = json.loads(ctx.read_text(path))
        except json.JSONDecodeError:
            continue
        for i, cell in enumerate(nb.get("cells", []) if isinstance(nb, dict) else []):
            if not isinstance(cell, dict) or cell.get("cell_type") != "code":
                continue
            code = _cell_source(cell)
            loc = f"{ctx.rel(path)}#cell{i}"

            for ref in _HF_REF.findall(code):
                out.append(
                    Component(
                        key=f"model:hf:{ref}",
                        type=ComponentType.MODEL,
                        name=ref,
                        location=loc,
                        provenance=Provenance(source=f"hf:{ref}", author=ref.split("/")[0]),
                        metadata={"hf_repo": ref, "from_notebook": True},
                    )
                )
            for ref in _LOAD_DATASET.findall(code):
                out.append(
                    Component(
                        key=f"dataset:{ref}",
                        type=ComponentType.DATASET,
                        name=ref,
                        location=loc,
                        provenance=Provenance(source=f"hf-dataset:{ref}" if "/" in ref else ref),
                        metadata={"hf_dataset": "/" in ref, "from_notebook": True},
                    )
                )
            for install in _PIP.findall(code):
                for token in install.split():
                    if token.startswith("-"):
                        continue
                    m = _PKG.match(token)
                    if not m:
                        continue
                    name, ver = m.group(1).lower().replace("_", "-"), m.group(2)
                    out.append(
                        Component(
                            key=f"pypi:{name}@{ver or '*'}",
                            type=ComponentType.LIBRARY,
                            name=name,
                            location=loc,
                            provenance=Provenance(source="pypi", version=ver, pinned=bool(ver)),
                            metadata={"ecosystem": "PyPI", "from_notebook": True},
                        )
                    )
    return out


register("notebooks", discover)
