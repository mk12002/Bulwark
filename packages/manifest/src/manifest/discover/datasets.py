"""Dataset discovery: load_dataset refs and local data files."""

from __future__ import annotations

import re

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register

_LOAD_DATASET = re.compile(r"""load_dataset\s*\(\s*["']([\w\-./]+)["']""")
_DATA_SUFFIXES = {".csv", ".parquet", ".jsonl", ".arrow", ".tsv"}


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []
    seen: set[str] = set()

    for path in ctx.code_files() + ctx.by_suffix(".json", ".yaml", ".yml"):
        for ref in _LOAD_DATASET.findall(ctx.read_text(path)):
            if ref in seen:
                continue
            seen.add(ref)
            out.append(
                Component(
                    key=f"dataset:{ref}",
                    type=ComponentType.DATASET,
                    name=ref,
                    location=ctx.rel(path),
                    provenance=Provenance(source=f"hf-dataset:{ref}" if "/" in ref else ref),
                    metadata={"hf_dataset": "/" in ref},
                )
            )

    for path in ctx.by_suffix(*_DATA_SUFFIXES):
        rel = ctx.rel(path)
        out.append(
            Component(
                key=f"dataset:{rel}",
                type=ComponentType.DATASET,
                name=path.name,
                location=rel,
                provenance=Provenance(source="local"),
                metadata={"local_data_file": True, "format": path.suffix.lstrip(".")},
            )
        )
    return out


register("datasets", discover)
