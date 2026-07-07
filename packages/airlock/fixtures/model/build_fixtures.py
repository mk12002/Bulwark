"""Generate the benign, inert model fixtures used by tests and demos.

Run from the repo root:  ``python fixtures/model/build_fixtures.py``

SAFETY: the "poisoned" pickle is never executed by Airlock (detection is static
opcode inspection). Its simulated payload is a harmless ``echo`` of a sentinel
marker — nothing destructive, no network, no filesystem harm. See CLAUDE.md
Principle 1: fixtures are intentionally vulnerable but strictly inert.
"""

from __future__ import annotations

import json
import pickle
import struct
import zipfile
from pathlib import Path

SENTINEL = "AIRLOCK_SENTINEL"
FIXTURE_ROOT = Path(__file__).resolve().parent


class _ShellPayload:
    """A class whose __reduce__ *simulates* a pickle RCE payload — inert.

    If this object were ever unpickled it would run ``os.system`` with a benign
    echo. Airlock never unpickles it; it only reads the opcodes. This exists
    solely so the M1 detector has something to trip on.
    """

    def __reduce__(self):  # type: ignore[no-untyped-def]
        import os

        return (os.system, (f"echo {SENTINEL}",))


def _write_safetensors(path: Path) -> None:
    """Write a minimal valid safetensors file (empty tensor set)."""
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode("utf-8")
    with path.open("wb") as fh:
        fh.write(struct.pack("<Q", len(header)))
        fh.write(header)


def _write_checksums(manifest: Path, *files: Path) -> None:
    """Write a SHA256SUMS manifest with the *correct* hashes of the given files."""
    import hashlib

    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}" for f in files]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_poisoned(root: Path) -> Path:
    """A pickle artifact that trips M1 (os.system) — inert, never executed."""
    target = root / "poisoned"
    target.mkdir(parents=True, exist_ok=True)
    (target / "pytorch_model.bin").write_bytes(pickle.dumps(_ShellPayload()))
    (target / "config.json").write_text(
        json.dumps({"model_type": "demo", "hidden_size": 8}, indent=2),
        encoding="utf-8",
    )
    return target


def build_remote_code(root: Path) -> Path:
    """A config enabling trust_remote_code + custom modeling code (M5)."""
    target = root / "remote_code"
    target.mkdir(parents=True, exist_ok=True)
    _write_safetensors(target / "model.safetensors")
    (target / "config.json").write_text(
        json.dumps(
            {
                "model_type": "custom",
                "trust_remote_code": True,
                "auto_map": {"AutoModel": "modeling_custom.CustomModel"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (target / "modeling_custom.py").write_text(
        "# benign fixture: presence alone should trip M5\nclass CustomModel:\n    pass\n",
        encoding="utf-8",
    )
    (target / "README.md").write_text("# Custom model\nBenign fixture.\n", encoding="utf-8")
    _write_checksums(target / "sha256sums.txt", target / "model.safetensors")
    return target


def build_archive_smuggle(root: Path) -> Path:
    """A zip-based artifact smuggling a script member (M6) — script is inert."""
    target = root / "archive_smuggle"
    target.mkdir(parents=True, exist_ok=True)
    bin_path = target / "pytorch_model.bin"
    with zipfile.ZipFile(bin_path, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"weights": [0, 1, 2]}))
        zf.writestr("archive/data/0", b"\x00\x00\x00\x00")
        zf.writestr("archive/setup.py", "# benign fixture marker: AIRLOCK_SENTINEL\n")
    (target / "config.json").write_text(json.dumps({"model_type": "demo"}), encoding="utf-8")
    return target


def build_clean(root: Path) -> Path:
    """A clean safetensors model with a model card and checksums — no findings."""
    target = root / "clean"
    target.mkdir(parents=True, exist_ok=True)
    _write_safetensors(target / "model.safetensors")
    (target / "config.json").write_text(
        json.dumps({"model_type": "bert", "hidden_size": 768}, indent=2),
        encoding="utf-8",
    )
    (target / "README.md").write_text(
        "# Clean demo model\n\nA benign safetensors fixture with provenance.\n",
        encoding="utf-8",
    )
    _write_checksums(target / "sha256sums.txt", target / "model.safetensors")
    return target


def build_all(root: Path | None = None) -> dict[str, Path]:
    """Build every model fixture under ``root`` (defaults to this directory)."""
    base = root or FIXTURE_ROOT
    return {
        "poisoned": build_poisoned(base),
        "remote_code": build_remote_code(base),
        "archive_smuggle": build_archive_smuggle(base),
        "clean": build_clean(base),
    }


if __name__ == "__main__":
    built = build_all()
    for name, path in built.items():
        print(f"built {name}: {path}")
