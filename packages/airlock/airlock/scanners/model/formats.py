"""Serialization-format classification (M4 advisory).

Recognizes memory-safe formats (safetensors, GGUF) so that a pickle-only artifact
is flagged for lacking a safe alternative, and surfaces the full format inventory.
"""

from __future__ import annotations

from bulwark_core.signals import SignalBundle

from airlock.scanners.model.loader import ModelInventory

_GGUF_MAGIC = b"GGUF"


def _is_valid_gguf(path_bytes: bytes) -> bool:
    return path_bytes[:4] == _GGUF_MAGIC


def collect(inventory: ModelInventory, bundle: SignalBundle) -> None:
    """Emit format signals; flag pickle-without-a-safe-format as an M4 advisory."""
    pickles = inventory.pickles()
    safe = inventory.safe_formats()

    formats = sorted({f.suffix for f in inventory.files if f.suffix})
    if formats:
        bundle.add("model.formats", formats)

    # Note recognized safe formats (informational; also satisfies "a safe format exists").
    for gguf in inventory.files:
        if gguf.suffix in {".gguf", ".ggml"}:
            try:
                head = gguf.path.read_bytes()[:4]
            except OSError:
                head = b""
            bundle.add(
                "model.safe_format",
                gguf.relpath,
                path=gguf.relpath,
                evidence=f"memory-safe GGUF format{'' if _is_valid_gguf(head) else ' (bad magic)'}",
            )

    if pickles and not safe:
        names = ", ".join(f.relpath for f in pickles[:5])
        bundle.add(
            "model.pickle_without_safetensors",
            True,
            path=names,
            evidence=f"pickle weights with no safetensors/GGUF alternative: {names}",
        )
