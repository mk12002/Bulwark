"""Archive smuggling + decompression-bomb inspection (M6).

PyTorch/ckpt artifacts are zip archives. We enumerate members without extracting
and flag absolute/traversal member names, unexpected executable/script types, and
decompression bombs (huge declared uncompressed size or extreme compression
ratio). Member counts and reads are bounded (see :mod:`bulwark_core.limits`).
"""

from __future__ import annotations

import zipfile

from bulwark_core.limits import DEFAULT_LIMITS, Limits
from bulwark_core.signals import SignalBundle

from airlock.scanners.model.loader import ArtifactFile

_ZIP_MAGIC = b"PK\x03\x04"

_EXPECTED_SUFFIXES = {
    ".pkl",
    ".bin",
    ".json",
    ".txt",
    ".md",
    ".model",
    ".npy",
    ".data",
    ".storage",
    "",  # torch stores tensor data blobs with no extension
}

_DANGEROUS_SUFFIXES = {
    ".py",
    ".pyc",
    ".sh",
    ".bash",
    ".bat",
    ".cmd",
    ".ps1",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".elf",
}


def _is_zip(file: ArtifactFile) -> bool:
    try:
        with file.path.open("rb") as fh:
            return fh.read(4) == _ZIP_MAGIC
    except OSError:
        return False


def _suffix_of(member: str) -> str:
    base = member.rsplit("/", 1)[-1]
    dot = base.rfind(".")
    return base[dot:].lower() if dot > 0 else ""


def _is_traversal(member: str) -> bool:
    norm = member.replace("\\", "/")
    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
        return True
    return any(part == ".." for part in norm.split("/"))


def _check_bomb(
    zf: zipfile.ZipFile, file: ArtifactFile, bundle: SignalBundle, limits: Limits
) -> bool:
    """Emit an archive.zip_bomb signal for oversized/over-compressed archives."""
    total_uncompressed = 0
    total_compressed = 0
    for info in zf.infolist():
        total_uncompressed += info.file_size
        total_compressed += info.compress_size
    ratio = (total_uncompressed / total_compressed) if total_compressed else 0.0
    bomb = (
        total_uncompressed > limits.max_uncompressed_bytes or ratio > limits.max_compression_ratio
    )
    if bomb:
        bundle.add(
            "archive.zip_bomb",
            file.relpath,
            path=file.relpath,
            detail=f"ratio={ratio:.0f}x",
            evidence=(
                f"decompression bomb: {total_uncompressed} bytes uncompressed "
                f"({ratio:.0f}x compression ratio)"
            ),
        )
    return bomb


def collect(
    files: list[ArtifactFile], bundle: SignalBundle, limits: Limits = DEFAULT_LIMITS
) -> None:
    """Emit M6 signals for bombs and suspicious members inside zip artifacts."""
    for file in files:
        if not (file.is_pickle or file.suffix in {".zip", ".ckpt", ".pt"}):
            continue
        if not _is_zip(file):
            continue
        try:
            with zipfile.ZipFile(file.path) as zf:
                # A bomb is flagged from headers alone; we still scan member names
                # (cheap) but never extract oversized members.
                _check_bomb(zf, file, bundle, limits)
                for idx, member in enumerate(zf.namelist()):
                    if idx >= limits.max_archive_members:
                        break
                    _check_member(member, file, bundle)
        except (zipfile.BadZipFile, OSError):
            continue


def _check_member(member: str, file: ArtifactFile, bundle: SignalBundle) -> None:
    if _is_traversal(member):
        bundle.add(
            "archive.path_traversal",
            member,
            path=file.relpath,
            detail=member,
            evidence=f"traversal/absolute member: {member}",
        )
        return
    suffix = _suffix_of(member)
    if suffix in _DANGEROUS_SUFFIXES:
        bundle.add(
            "archive.unexpected_member",
            member,
            path=file.relpath,
            detail=member,
            evidence=f"executable/script member: {member}",
        )
    elif suffix not in _EXPECTED_SUFFIXES:
        bundle.add(
            "archive.unexpected_member",
            member,
            path=file.relpath,
            detail=member,
            evidence=f"unexpected member type: {member}",
        )
