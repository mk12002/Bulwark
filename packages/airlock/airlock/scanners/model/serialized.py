"""Non-pickle serialized formats: numpy object arrays, Keras Lambda, ONNX (M1/M5/M6).

- **numpy** ``.npy``/``.npz``: an *object*-dtype array embeds a pickle, so it is a
  code-execution vector under ``numpy.load(allow_pickle=True)``. We locate the
  embedded pickle and run the standard opcode inspection over it.
- **Keras** ``.h5``/``.hdf5``/``.keras``: ``Lambda`` layers store marshalled Python
  that Keras executes on load — a real RCE vector.
- **ONNX** ``.onnx``: flag external-data references that use traversal paths and
  custom Python operators (``PyOp``/``pyfunc``).

Everything is byte-level inspection — no numpy/keras/onnx import, nothing executed.
"""

from __future__ import annotations

import ast
import io
import zipfile

from airlock.core.limits import DEFAULT_LIMITS, Limits
from airlock.core.signals import SignalBundle
from airlock.scanners.model.loader import ArtifactFile
from airlock.scanners.model.pickle_scan import analyze_stream

_NPY_MAGIC = b"\x93NUMPY"
_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_MAX_HEADER = 1 << 16
_SCAN_BYTES = 4 * 1024 * 1024  # cap raw byte-scan reads


# --------------------------------------------------------------------------- #
# numpy
# --------------------------------------------------------------------------- #


def _parse_npy_object_pickle(data: bytes, limits: Limits) -> bytes | None:
    """If ``data`` is an object-dtype .npy, return the embedded pickle bytes."""
    if data[:6] != _NPY_MAGIC:
        return None
    major = data[6]
    try:
        if major == 1:
            hlen = int.from_bytes(data[8:10], "little")
            hstart = 10
        else:
            hlen = int.from_bytes(data[8:12], "little")
            hstart = 12
    except IndexError:
        return None
    if hlen <= 0 or hlen > _MAX_HEADER:
        return None
    header = data[hstart : hstart + hlen].decode("latin1", errors="replace")
    try:
        meta = ast.literal_eval(header.strip())
    except (ValueError, SyntaxError):
        return None
    if not isinstance(meta, dict) or "O" not in str(meta.get("descr", "")):
        return None  # not an object array → no embedded pickle → safe
    payload = data[hstart + hlen :]
    return payload[: limits.max_member_bytes] if payload else None


def _emit_pickle(label: str, blob: bytes, bundle: SignalBundle, limits: Limits) -> None:
    """Run pickle inspection over an embedded stream and emit the usual signals."""
    bundle.add("model.pickle_file", label, path=label, evidence=f"embedded pickle in {label}")
    analysis = analyze_stream(blob, limits)
    if analysis.has_reduce:
        bundle.add("pickle.has_reduce", True, path=label)
    for name, pos in analysis.imports:
        bundle.add(
            "pickle.imports",
            name,
            path=label,
            detail=f"opcode@{pos}" if pos >= 0 else None,
            evidence=name,
        )
    for name in analysis.nested_imports:
        bundle.add("pickle.imports", name, path=label, detail="nested-base64", evidence=name)
    for s in analysis.strings:
        bundle.add("pickle.strings", s, path=label, evidence=" ".join(s.split()))


def _collect_numpy(file: ArtifactFile, bundle: SignalBundle, limits: Limits) -> None:
    try:
        raw = file.path.read_bytes()
    except OSError:
        return
    if file.suffix == ".npz":
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for idx, info in enumerate(zf.infolist()):
                    if (
                        idx >= limits.max_archive_members
                        or info.file_size > limits.max_member_bytes
                    ):
                        continue
                    blob = _parse_npy_object_pickle(zf.read(info), limits)
                    if blob:
                        _emit_pickle(f"{file.relpath}::{info.filename}", blob, bundle, limits)
        except (zipfile.BadZipFile, OSError):
            return
        return
    blob = _parse_npy_object_pickle(raw, limits)
    if blob:
        _emit_pickle(f"{file.relpath} (object array)", blob, bundle, limits)


# --------------------------------------------------------------------------- #
# Keras
# --------------------------------------------------------------------------- #


def _collect_keras(file: ArtifactFile, bundle: SignalBundle) -> None:
    if file.suffix == ".keras":
        _collect_keras_zip(file, bundle)
        return
    try:
        with file.path.open("rb") as fh:
            head = fh.read(8)
            body = fh.read(_SCAN_BYTES)
    except OSError:
        return
    if head != _HDF5_MAGIC:
        return
    if b"Lambda" in body and (b"function" in body or b"module" in body):
        bundle.add(
            "model.keras_lambda",
            file.relpath,
            path=file.relpath,
            evidence="HDF5 model contains a Lambda layer (embedded Python executed on load)",
        )


def _collect_keras_zip(file: ArtifactFile, bundle: SignalBundle) -> None:
    try:
        with zipfile.ZipFile(file.path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            for name in names:
                text = zf.read(name)[:_SCAN_BYTES].decode("utf-8", errors="replace")
                if '"class_name": "Lambda"' in text or '"class_name":"Lambda"' in text:
                    bundle.add(
                        "model.keras_lambda",
                        file.relpath,
                        path=file.relpath,
                        detail=name,
                        evidence="Keras config declares a Lambda layer (embedded Python)",
                    )
                    return
    except (zipfile.BadZipFile, OSError):
        return


# --------------------------------------------------------------------------- #
# ONNX
# --------------------------------------------------------------------------- #


def _collect_onnx(file: ArtifactFile, bundle: SignalBundle) -> None:
    try:
        with file.path.open("rb") as fh:
            body = fh.read(_SCAN_BYTES)
    except OSError:
        return
    if b"../" in body or b"..\\" in body:
        bundle.add(
            "model.onnx_external",
            file.relpath,
            path=file.relpath,
            evidence="ONNX references an external-data path containing '..' (traversal)",
        )
    for marker in (b"PyOp", b"pyfunc"):
        if marker in body:
            bundle.add(
                "model.onnx_custom_op",
                file.relpath,
                path=file.relpath,
                detail=marker.decode(),
                evidence=f"ONNX references a custom Python operator ({marker.decode()})",
            )
            break


# --------------------------------------------------------------------------- #


def collect(
    files: list[ArtifactFile], bundle: SignalBundle, limits: Limits = DEFAULT_LIMITS
) -> None:
    """Dispatch each non-pickle serialized file to its analyzer."""
    for file in files:
        if file.is_numpy:
            _collect_numpy(file, bundle, limits)
        elif file.is_keras:
            _collect_keras(file, bundle)
        elif file.is_onnx:
            _collect_onnx(file, bundle)
