"""Format / extension confusion detection (M6 — scanner-evasion by format spoofing).

Motivated by the 2025 picklescan bypass class (e.g. CVE-2025-10155): a malicious
pickle renamed to a "safe" extension (``.safetensors``, ``.gguf``, …) or given a
non-pickle extension makes an extension-based classifier skip the pickle scan
entirely, so the payload ships undetected.

Airlock defends by **sniffing content, not trusting the extension**: if a file whose
extension implies a non-pickle/safe format actually contains a pickle stream, we
flag the deception (``model.format_mismatch``) *and* run the pickle disassembler on
it so any dangerous payload still trips M1/M2. Detection is byte-level; nothing is
deserialized.
"""

from __future__ import annotations

from bulwark_core.limits import DEFAULT_LIMITS, Limits
from bulwark_core.signals import SignalBundle

from airlock.scanners.model import pickle_scan
from airlock.scanners.model.loader import ArtifactFile

# Pickle protocol header: 0x80 followed by a protocol byte in 2..5.
_PICKLE_PROTO_BYTES = {2, 3, 4, 5}


def _looks_like_pickle_content(file: ArtifactFile) -> bool:
    """Cheap magic-byte pre-filter: does this file start like a pickle stream?"""
    try:
        with file.path.open("rb") as fh:
            head = fh.read(2)
    except OSError:
        return False
    if len(head) >= 2 and head[0] == 0x80 and head[1] in _PICKLE_PROTO_BYTES:
        return True
    # Protocol-0/1 pickles have no proto byte; treat a leading classic-GLOBAL 'c'
    # or MARK '(' as a candidate only when the extension claims a safe binary format.
    return head[:1] in (b"c", b"(") and file.is_safe_format


def collect(
    files: list[ArtifactFile],
    bundle: SignalBundle,
    limits: Limits = DEFAULT_LIMITS,
    *,
    strict: bool = False,
) -> None:
    """Flag files whose content is a pickle but whose extension says otherwise."""
    for file in files:
        # Pickle-family files are scanned by pickle_scan; numpy/keras legitimately
        # embed pickles and have dedicated handling. Everything else is a candidate
        # for extension spoofing.
        if file.is_pickle or file.is_numpy or file.is_keras:
            continue
        if not _looks_like_pickle_content(file):
            continue

        analyses = pickle_scan.analyze_file(file, limits)
        # Confirm it really disassembles as a pickle (has imports or reduce), so a
        # coincidental leading byte on a genuine safe-format file is not misreported.
        confirmed = any(a.imports or a.has_reduce for a in analyses.values())
        if not confirmed:
            continue

        claimed = file.suffix or "(no extension)"
        bundle.add(
            "model.format_mismatch",
            file.relpath,
            path=file.relpath,
            detail=claimed,
            evidence=(
                f"{file.relpath} has extension '{claimed}' but its bytes are a pickle "
                f"stream — possible format spoofing to evade an extension-based scanner"
            ),
        )
        # Re-emit full pickle signals so a dangerous hidden payload still trips M1/M2.
        pickle_scan.emit_analyses(file.relpath, analyses, bundle, strict=strict)
