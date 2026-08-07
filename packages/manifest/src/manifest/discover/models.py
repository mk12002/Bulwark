"""Model discovery: local weight files and model refs in code/config."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from manifest.bom.model import Component, ComponentType, Provenance
from manifest.discover.base import DiscoveryContext, register

_WEIGHT_SUFFIXES = {
    ".safetensors",
    ".bin",
    ".gguf",
    ".ggml",
    ".pt",
    ".pth",
    ".ckpt",
    ".onnx",
    ".h5",
}
_SAFE_SUFFIXES = {".safetensors", ".gguf", ".ggml"}

# from_pretrained("org/name") / AutoModel.from_pretrained('org/name') / hf hub ids
_HF_REF = re.compile(
    r"""(?:from_pretrained|hf_hub_download|snapshot_download)\s*\(\s*["']([\w\-./]+/[\w\-.]+)["']""",
)
_MAX_HASH_BYTES = 64 * 1024 * 1024  # only hash smallish weight files


def _hash(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def discover(ctx: DiscoveryContext) -> list[Component]:
    out: list[Component] = []

    # Local weight files → model components (with a hash for provenance).
    for path in ctx.by_suffix(*_WEIGHT_SUFFIXES):
        rel = ctx.rel(path)
        digest = _hash(path)
        out.append(
            Component(
                key=f"model:{rel}",
                type=ComponentType.MODEL,
                name=path.name,
                location=rel,
                provenance=Provenance(source="local", hash=digest, pinned=digest is not None),
                metadata={
                    "format": path.suffix.lower().lstrip("."),
                    "memory_safe": path.suffix.lower() in _SAFE_SUFFIXES,
                    "local_weight_file": True,
                },
            )
        )

    # Model ids referenced in code/config (from_pretrained etc.).
    seen: set[str] = set()
    for path in ctx.code_files() + ctx.by_suffix(".json", ".yaml", ".yml", ".toml"):
        text = ctx.read_text(path)
        for ref in _HF_REF.findall(text):
            if ref in seen:
                continue
            seen.add(ref)
            out.append(
                Component(
                    key=f"model:hf:{ref}",
                    type=ComponentType.MODEL,
                    name=ref,
                    location=ctx.rel(path),
                    provenance=Provenance(source=f"hf:{ref}", author=ref.split("/")[0]),
                    metadata={"hf_repo": ref},
                )
            )
    return out


register("models", discover)
