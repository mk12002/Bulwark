"""Provenance & integrity gaps (M7).

Checks for a populated model card and for published hashes — and, when a
SHA256SUMS-style manifest is present, actually **verifies** the listed files
against it. A mismatch is a tampering signal (HIGH), not an advisory.
"""

from __future__ import annotations

import hashlib
import re

from bulwark_core.limits import DEFAULT_LIMITS
from bulwark_core.signals import SignalBundle

from airlock.scanners.model.loader import ArtifactFile, ModelInventory

_MODEL_CARD_NAMES = {"readme.md", "model_card.md", "modelcard.md"}
_CHECKSUM_MANIFESTS = {"sha256sums", "sha256sums.txt", "checksums.txt", "sha256sum.txt"}
_HASH_FILE_NAMES = _CHECKSUM_MANIFESTS | {
    "model.safetensors.index.json",
    "pytorch_model.bin.index.json",
}
_HASH_SUFFIXES = {".sha256", ".sig", ".sigstore", ".asc"}
_SHA256_LINE = re.compile(r"^([0-9a-fA-F]{64})\s[ *]?(.+)$")


def _has_model_card(inventory: ModelInventory) -> bool:
    for f in inventory.files:
        name = f.relpath.rsplit("/", 1)[-1].lower()
        if name in _MODEL_CARD_NAMES and f.size > 0:
            return True
    return False


def _has_hashes(inventory: ModelInventory) -> bool:
    for f in inventory.files:
        name = f.relpath.rsplit("/", 1)[-1].lower()
        if name in _HASH_FILE_NAMES or f.suffix in _HASH_SUFFIXES:
            return True
    return False


def _sha256(file: ArtifactFile) -> str | None:
    try:
        h = hashlib.sha256()
        with file.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _by_name(inventory: ModelInventory) -> dict[str, ArtifactFile]:
    return {f.relpath.rsplit("/", 1)[-1]: f for f in inventory.files}


def _verify_manifests(inventory: ModelInventory, bundle: SignalBundle) -> bool:
    """Verify any SHA256SUMS manifest; emit mismatches. Returns True if one existed."""
    by_name = _by_name(inventory)
    found_manifest = False
    for f in inventory.files:
        if f.relpath.rsplit("/", 1)[-1].lower() not in _CHECKSUM_MANIFESTS:
            continue
        found_manifest = True
        try:
            lines = f.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            m = _SHA256_LINE.match(line.strip())
            if not m:
                continue
            expected, name = m.group(1).lower(), m.group(2).strip().rsplit("/", 1)[-1]
            target = by_name.get(name)
            if target is None:
                continue
            if target.size > DEFAULT_LIMITS.max_member_bytes:
                continue  # don't hash pathologically large files
            actual = _sha256(target)
            if actual is not None and actual != expected:
                bundle.add(
                    "provenance.hash_mismatch",
                    name,
                    path=target.relpath,
                    detail=f"expected {expected[:12]}…, got {actual[:12]}…",
                    evidence=f"{name} does not match its published SHA256 checksum",
                )
    return found_manifest


def collect(inventory: ModelInventory, bundle: SignalBundle) -> None:
    """Emit M7 signals: verified-hash mismatches (HIGH) and missing card/hashes."""
    _verify_manifests(inventory, bundle)
    if not _has_model_card(inventory):
        bundle.add(
            "provenance.missing_model_card",
            True,
            path=inventory.target,
            evidence="no populated model card (README.md/model_card.md) found",
        )
    if not _has_hashes(inventory):
        bundle.add(
            "provenance.missing_hashes",
            True,
            path=inventory.target,
            evidence="no published checksums/signature files found",
        )
