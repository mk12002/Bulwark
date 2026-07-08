"""Pickle opcode inspection (M1/M2/M3) — inspection only, never execution.

Uses :func:`pickletools.genops`, which *parses* the opcode stream without running
it. We resolve the callables referenced by ``GLOBAL``/``STACK_GLOBAL``, note the
presence of ``REDUCE``/``NEWOBJ`` construction opcodes, and collect embedded
strings. Handles raw pickle files (streamed, never fully loaded) and zip-wrapped
archives (PyTorch ``.pt``/``.bin``/``.ckpt`` are zips containing ``data.pkl``).

Hardening: opcode counts and member sizes are capped (see :mod:`bulwark_core.limits`)
so a hostile stream cannot hang or OOM the scanner. Base64-encoded nested pickles
are decoded one level deep to catch staged payloads.
"""

from __future__ import annotations

import base64
import binascii
import io
import pickletools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from bulwark_core.limits import DEFAULT_LIMITS, Limits
from bulwark_core.signals import SignalBundle

from airlock.scanners.model.loader import ArtifactFile

_ZIP_MAGIC = b"PK\x03\x04"
_PICKLE_PROTO = b"\x80"

_STRING_OPCODES = {
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "UNICODE",
    "SHORT_BINSTRING",
    "BINSTRING",
    "STRING",
}
_GLOBAL_OPCODES = {"GLOBAL", "INST"}
_STACK_GLOBAL_OPCODES = {"STACK_GLOBAL"}
_REDUCE_OPCODES = {"REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "BUILD"}

_B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

# Fickling-style allowlist (opt-in "strict" mode): the top-level modules a benign
# ML pickle is expected to import from. Anything outside this set is surfaced as an
# *unexpected* import — this catches novel malicious callables a denylist has never
# seen, rather than only known-dangerous names. Empirically, real HuggingFace pickle
# weights import only from a tiny set (torch, collections, numpy, builtins).
SAFE_PICKLE_MODULES = frozenset(
    {
        "torch",
        "collections",
        "numpy",
        "__builtin__",
        "builtins",
        "copyreg",
        "copy_reg",
        "_codecs",
        "encodings",
        "functools",
        "datetime",
        "decimal",
        "dataclasses",
        "typing",
        "argparse",
        "pandas",
        "sklearn",
        "scipy",
        "joblib",
        "transformers",
        "tokenizers",
        "sentencepiece",
        "PIL",
    }
)


def _top_module(callable_name: str) -> str:
    return callable_name.split(".", 1)[0]


@dataclass
class PickleAnalysis:
    """Structured result of disassembling one pickle stream."""

    imports: list[tuple[str, int]] = field(default_factory=list)  # (callable, pos)
    strings: list[str] = field(default_factory=list)
    nested_imports: list[str] = field(default_factory=list)  # resolved in decoded blobs
    has_reduce: bool = False
    opcode_count: int = 0
    truncated: bool = False  # opcode cap hit
    error: str | None = None


def _resolve_global_arg(arg: object) -> str | None:
    """Resolve a GLOBAL opcode argument ('module name') to 'module.name'."""
    if not isinstance(arg, str):
        return None
    module, _, name = arg.partition(" ")
    name = name.strip()
    module = module.strip()
    if module and name:
        return f"{module}.{name}"
    return module or name or None


_MEMO_STORE_AUTO = {"MEMOIZE"}
_MEMO_STORE_INDEXED = {"PUT", "BINPUT", "LONG_BINPUT"}
_MEMO_GET = {"GET", "BINGET", "LONG_BINGET"}


def _run_genops(reader: BinaryIO, limits: Limits) -> PickleAnalysis:
    """Disassemble a pickle stream from a binary reader, with an opcode cap.

    Resolves ``STACK_GLOBAL`` operands via a memo-aware view of the string stack:
    a module/name reused through the pickle memo (``BINGET``) is re-pushed so the
    global still resolves — catching payloads the naive "last two strings" misses.
    """
    result = PickleAnalysis()
    string_stack: list[str] = []
    memo: dict[int, str | None] = {}
    memo_auto = 0
    prev_string: str | None = None
    try:
        for opcode, arg, pos in pickletools.genops(reader):
            result.opcode_count += 1
            if result.opcode_count > limits.max_pickle_opcodes:
                result.truncated = True
                break
            name = opcode.name
            cur_string: str | None = None

            if name in _STRING_OPCODES and isinstance(arg, str):
                cur_string = arg
                string_stack.append(arg)
                if len(result.strings) < limits.max_strings:
                    result.strings.append(arg[: limits.max_string_len])
            elif name in _MEMO_STORE_AUTO:
                memo[memo_auto] = prev_string
                memo_auto += 1
            elif name in _MEMO_STORE_INDEXED and isinstance(arg, int):
                memo[arg] = prev_string
            elif name in _MEMO_GET and isinstance(arg, int):
                recalled = memo.get(arg)
                if isinstance(recalled, str):
                    cur_string = recalled
                    string_stack.append(recalled)

            if name in _GLOBAL_OPCODES:
                resolved = _resolve_global_arg(arg)
                if resolved:
                    result.imports.append((resolved, pos if isinstance(pos, int) else -1))
            elif name in _STACK_GLOBAL_OPCODES and len(string_stack) >= 2:
                module, member = string_stack[-2], string_stack[-1]
                result.imports.append((f"{module}.{member}", pos if isinstance(pos, int) else -1))

            if name in _REDUCE_OPCODES:
                result.has_reduce = True
            prev_string = cur_string
    except Exception as exc:  # genops raises on truncated/invalid streams
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def analyze_stream(data: bytes, limits: Limits = DEFAULT_LIMITS) -> PickleAnalysis:
    """Disassemble a raw pickle byte stream, then decode nested base64 pickles."""
    result = _run_genops(io.BytesIO(data), limits)
    _scan_nested(result, limits)
    return result


def _looks_like_pickle(blob: bytes) -> bool:
    return blob[:1] == _PICKLE_PROTO or blob[:2] == _ZIP_MAGIC[:2]


def _scan_nested(result: PickleAnalysis, limits: Limits) -> None:
    """Decode base64-looking strings; if they are pickles, disassemble one level."""
    for s in result.strings:
        if not _B64_RE.match(s):
            continue
        try:
            blob = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not blob or len(blob) > limits.max_nested_blob_bytes or not _looks_like_pickle(blob):
            continue
        inner = _run_genops(io.BytesIO(blob), limits)
        for name, _pos in inner.imports:
            result.nested_imports.append(name)


def _analyze_zip(path: Path, limits: Limits) -> dict[str, PickleAnalysis]:
    """Analyze pickle members inside a zip, streaming from disk with size caps."""
    import zipfile

    out: dict[str, PickleAnalysis] = {}
    try:
        with zipfile.ZipFile(path) as zf:
            for idx, info in enumerate(zf.infolist()):
                if idx >= limits.max_archive_members:
                    break
                lname = info.filename.lower()
                if not lname.endswith(".pkl"):
                    continue
                if info.file_size > limits.max_member_bytes:
                    out[info.filename] = PickleAnalysis(error="member exceeds size limit; skipped")
                    continue
                with zf.open(info) as fh:
                    out[info.filename] = analyze_stream(fh.read(), limits)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"": PickleAnalysis(error=f"{type(exc).__name__}: {exc}")}
    return out


_GZIP_MAGIC = b"\x1f\x8b"
_ZLIB_FIRST = 0x78
_ZLIB_SECOND = {0x01, 0x9C, 0xDA, 0x5E}


def _decompress(head: bytes, path: Path, limits: Limits) -> bytes | None:
    """Bounded gzip/zlib decompression for compressed pickles (e.g. joblib)."""
    import zlib

    if head[:2] == _GZIP_MAGIC:
        wbits = 16 + zlib.MAX_WBITS
    elif len(head) >= 2 and head[0] == _ZLIB_FIRST and head[1] in _ZLIB_SECOND:
        wbits = zlib.MAX_WBITS
    else:
        return None
    try:
        raw = path.read_bytes()
        return zlib.decompressobj(wbits).decompress(raw, limits.max_member_bytes)
    except (OSError, zlib.error):
        return None


def analyze_file(file: ArtifactFile, limits: Limits = DEFAULT_LIMITS) -> dict[str, PickleAnalysis]:
    """Analyze one artifact file, returning {member_name: analysis}.

    Raw pickles are streamed (never fully read into memory); zip archives are
    opened from disk; gzip/zlib-compressed pickles are decompressed (bounded) and
    then inspected. Member name is "" for a raw pickle.
    """
    try:
        with file.path.open("rb") as fh:
            head = fh.read(4)
            fh.seek(0)
            if head == _ZIP_MAGIC:
                return _analyze_zip(file.path, limits)
            decompressed = _decompress(head, file.path, limits)
            if decompressed is not None:
                return {"": analyze_stream(decompressed, limits)}
            return {"": analyze_stream_from(fh, limits)}
    except OSError as exc:  # pragma: no cover - unreadable file
        return {"": PickleAnalysis(error=f"unreadable: {exc}")}


def analyze_stream_from(reader: BinaryIO, limits: Limits = DEFAULT_LIMITS) -> PickleAnalysis:
    """Disassemble a raw pickle directly from a binary reader (streamed)."""
    result = _run_genops(reader, limits)
    _scan_nested(result, limits)
    return result


def _member_label(relpath: str, member: str) -> str:
    return f"{relpath}::{member}" if member else relpath


def emit_analyses(
    relpath: str,
    analyses: dict[str, PickleAnalysis],
    bundle: SignalBundle,
    *,
    strict: bool = False,
) -> None:
    """Emit pickle signals for one file's disassembly result(s).

    Shared by the pickle collector and the format-confusion analyzer, so a pickle
    hidden under a non-pickle extension still produces full M1/M2 findings. When
    ``strict`` is set, also emit ``pickle.unexpected_module`` for imports whose
    top-level module is outside the ML allowlist (Fickling-style).
    """
    for member, analysis in analyses.items():
        label = _member_label(relpath, member)
        if analysis.has_reduce:
            bundle.add("pickle.has_reduce", True, path=label)
        for callable_name, pos in analysis.imports:
            bundle.add(
                "pickle.imports",
                callable_name,
                path=label,
                detail=f"opcode@{pos}" if pos >= 0 else None,
                evidence=callable_name,
            )
            if strict and _top_module(callable_name) not in SAFE_PICKLE_MODULES:
                bundle.add(
                    "pickle.unexpected_module",
                    callable_name,
                    path=label,
                    detail=_top_module(callable_name),
                    evidence=f"{callable_name} (module not on the ML allowlist)",
                )
        for nested in analysis.nested_imports:
            bundle.add(
                "pickle.imports",
                nested,
                path=label,
                detail="nested-base64",
                evidence=f"{nested} (in a base64-encoded nested pickle)",
            )
        for s in analysis.strings:
            bundle.add("pickle.strings", s, path=label, evidence=_safe(s))


def collect(
    files: list[ArtifactFile],
    bundle: SignalBundle,
    limits: Limits = DEFAULT_LIMITS,
    *,
    strict: bool = False,
) -> None:
    """Emit pickle signals for every pickle-family file into the bundle."""
    for file in files:
        if not file.is_pickle:
            continue
        bundle.add("model.pickle_file", file.relpath, path=file.relpath)
        analyses = analyze_file(file, limits)
        emit_analyses(file.relpath, analyses, bundle, strict=strict)


def _safe(text: str) -> str:
    """Collapse whitespace so evidence stays on one line."""
    return " ".join(text.split())


def has_pickle(path: Path) -> bool:
    """Best-effort: does the file at ``path`` look pickle-based (raw or zip)?"""
    try:
        with path.open("rb") as fh:
            head = fh.read(2)
    except OSError:
        return False
    return head[:1] == _PICKLE_PROTO or head[:2] == _ZIP_MAGIC[:2]
