"""Focused tests for individual model analyzers (edge cases)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from airlock.scanners.model import archive, provenance
from airlock.scanners.model.loader import ArtifactFile, ModelInventory
from bulwark_core.signals import SignalBundle


def _artifact(path: Path) -> ArtifactFile:
    return ArtifactFile(
        path=path,
        relpath=path.name,
        size=path.stat().st_size,
        suffix=path.suffix.lower(),
    )


def test_archive_detects_path_traversal(tmp_path: Path) -> None:
    bin_path = tmp_path / "model.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.txt", b"x")
        zf.writestr("archive/data.pkl", b"\x80\x04}")
    bin_path.write_bytes(buf.getvalue())

    bundle = SignalBundle(target="model")
    archive.collect([_artifact(bin_path)], bundle)
    assert bundle.by_name("archive.path_traversal")
    assert any("evil.txt" in s.value for s in bundle.by_name("archive.path_traversal"))


def test_archive_flags_executable_member(tmp_path: Path) -> None:
    bin_path = tmp_path / "model.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/payload.so", b"\x7fELF")
    bin_path.write_bytes(buf.getvalue())

    bundle = SignalBundle(target="model")
    archive.collect([_artifact(bin_path)], bundle)
    members = [s.value for s in bundle.by_name("archive.unexpected_member")]
    assert any(m.endswith("payload.so") for m in members)


def test_provenance_flags_missing_card_and_hashes(tmp_path: Path) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"\x00")
    inventory = ModelInventory(
        target=str(tmp_path),
        root=tmp_path,
        files=[_artifact(tmp_path / "model.safetensors")],
    )
    bundle = SignalBundle(target="model")
    provenance.collect(inventory, bundle)
    assert bundle.by_name("provenance.missing_model_card")
    assert bundle.by_name("provenance.missing_hashes")


def test_provenance_detects_hash_mismatch(tmp_path: Path) -> None:
    import hashlib

    (tmp_path / "model.bin").write_bytes(b"the real weights")
    wrong = hashlib.sha256(b"different content").hexdigest()
    (tmp_path / "sha256sums.txt").write_text(f"{wrong}  model.bin\n", encoding="utf-8")
    files = [_artifact(tmp_path / "model.bin"), _artifact(tmp_path / "sha256sums.txt")]
    inventory = ModelInventory(target=str(tmp_path), root=tmp_path, files=files)
    bundle = SignalBundle(target="model")
    provenance.collect(inventory, bundle)
    assert bundle.by_name("provenance.hash_mismatch")


def test_provenance_verifies_correct_hash(tmp_path: Path) -> None:
    import hashlib

    content = b"the real weights"
    (tmp_path / "model.bin").write_bytes(content)
    good = hashlib.sha256(content).hexdigest()
    (tmp_path / "sha256sums.txt").write_text(f"{good}  model.bin\n", encoding="utf-8")
    files = [_artifact(tmp_path / "model.bin"), _artifact(tmp_path / "sha256sums.txt")]
    inventory = ModelInventory(target=str(tmp_path), root=tmp_path, files=files)
    bundle = SignalBundle(target="model")
    provenance.collect(inventory, bundle)
    assert not bundle.by_name("provenance.hash_mismatch")


def test_provenance_clean_when_card_and_hashes_present(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# model", encoding="utf-8")
    (tmp_path / "sha256sums.txt").write_text("0 x", encoding="utf-8")
    files = [_artifact(tmp_path / "README.md"), _artifact(tmp_path / "sha256sums.txt")]
    inventory = ModelInventory(target=str(tmp_path), root=tmp_path, files=files)
    bundle = SignalBundle(target="model")
    provenance.collect(inventory, bundle)
    assert not bundle.by_name("provenance.missing_model_card")
    assert not bundle.by_name("provenance.missing_hashes")
