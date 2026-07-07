"""Tests for Tier 2 model formats: numpy, keras, onnx, compressed & memoized pickles, GGUF."""

from __future__ import annotations

import gzip
import json
import pickle
import struct
import zipfile
import zlib
from pathlib import Path

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner, pickle_scan, serialized
from airlock.scanners.model.loader import ArtifactFile
from bulwark_core.limits import DEFAULT_LIMITS
from bulwark_core.signals import SignalBundle


def _artifact(path: Path) -> ArtifactFile:
    return ArtifactFile(
        path=path, relpath=path.name, size=path.stat().st_size, suffix=path.suffix.lower()
    )


def _scan(d: Path):
    return ModelScanner(RuleEngine(load_rules())).scan(str(d))


class _Shell:
    def __reduce__(self):  # type: ignore[no-untyped-def]
        import os

        return (os.system, ("echo hi",))


def _write_npy_object(path: Path, obj: object) -> None:
    """Write a minimal object-dtype .npy whose data section is a pickle of obj."""
    payload = pickle.dumps(obj)
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header = header + " " * ((64 - (10 + len(header) + 1) % 64) % 64) + "\n"
    with path.open("wb") as fh:
        fh.write(b"\x93NUMPY\x01\x00")
        fh.write(struct.pack("<H", len(header)))
        fh.write(header.encode("latin1"))
        fh.write(payload)


# --------------------------------------------------------------------------- #
# numpy object arrays
# --------------------------------------------------------------------------- #


def test_npy_object_array_pickle_trips_m1(tmp_path: Path) -> None:
    d = tmp_path / "npy"
    d.mkdir()
    _write_npy_object(d / "weights.npy", _Shell())
    result = _scan(d)
    assert "M1" in {f.category for f in result.findings}


def test_plain_npy_is_not_flagged(tmp_path: Path) -> None:
    # A float .npy has no object pickle → no pickle findings.
    npy = tmp_path / "arr.npy"
    header = "{'descr': '<f4', 'fortran_order': False, 'shape': (2,), }"
    header = header + " " * ((64 - (10 + len(header) + 1) % 64) % 64) + "\n"
    with npy.open("wb") as fh:
        fh.write(b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode())
        fh.write(struct.pack("<2f", 1.0, 2.0))
    bundle = SignalBundle(target="model")
    serialized.collect([_artifact(npy)], bundle)
    assert bundle.by_name("pickle.imports") == []


def test_npz_object_member_trips_m1(tmp_path: Path) -> None:
    d = tmp_path / "npz"
    d.mkdir()
    inner = tmp_path / "inner.npy"
    _write_npy_object(inner, _Shell())
    with zipfile.ZipFile(d / "weights.npz", "w") as zf:
        zf.write(inner, "arr_0.npy")
    result = _scan(d)
    assert "M1" in {f.category for f in result.findings}


# --------------------------------------------------------------------------- #
# compressed pickles
# --------------------------------------------------------------------------- #


def test_gzip_compressed_pickle_is_scanned(tmp_path: Path) -> None:
    pkl = tmp_path / "model.pkl"
    pkl.write_bytes(gzip.compress(pickle.dumps(_Shell())))
    out = pickle_scan.analyze_file(_artifact(pkl))
    names = [n for a in out.values() for n, _ in a.imports]
    assert any(n.endswith(".system") for n in names)


def test_zlib_compressed_pickle_is_scanned(tmp_path: Path) -> None:
    pkl = tmp_path / "model.pkl"
    pkl.write_bytes(zlib.compress(pickle.dumps(_Shell())))
    out = pickle_scan.analyze_file(_artifact(pkl))
    names = [n for a in out.values() for n, _ in a.imports]
    assert any(n.endswith(".system") for n in names)


# --------------------------------------------------------------------------- #
# memo-aware stack resolution
# --------------------------------------------------------------------------- #


def test_memoized_global_is_resolved() -> None:
    # Hand-build a pickle where the module/name are memoized then referenced by
    # BINGET before STACK_GLOBAL — the naive "last two strings" would miss it.
    p = b"\x80\x04"  # PROTO 4
    p += b"\x8c\x02os"  # SHORT_BINUNICODE 'os'
    p += b"\x94"  # MEMOIZE (memo 0)
    p += b"\x8c\x06system"  # SHORT_BINUNICODE 'system'
    p += b"\x94"  # MEMOIZE (memo 1)
    p += b"h\x00"  # BINGET 0 -> 'os'
    p += b"h\x01"  # BINGET 1 -> 'system'
    p += b"\x93"  # STACK_GLOBAL
    p += b"."  # STOP
    analysis = pickle_scan.analyze_stream(p)
    assert any(name == "os.system" for name, _ in analysis.imports)


# --------------------------------------------------------------------------- #
# keras / onnx (byte-level heuristics)
# --------------------------------------------------------------------------- #


def test_keras_h5_lambda_is_flagged(tmp_path: Path) -> None:
    d = tmp_path / "keras"
    d.mkdir()
    h5 = d / "model.h5"
    h5.write_bytes(b"\x89HDF\r\n\x1a\n" + b'...{"class_name": "Lambda", "function": "..."}...')
    assert "M5" in {f.category for f in _scan(d).findings}


def test_keras_v3_zip_lambda_is_flagged(tmp_path: Path) -> None:
    d = tmp_path / "keras3"
    d.mkdir()
    with zipfile.ZipFile(d / "model.keras", "w") as zf:
        zf.writestr("config.json", json.dumps({"layers": [{"class_name": "Lambda"}]}))
    assert "M5" in {f.category for f in _scan(d).findings}


def test_onnx_custom_python_op_is_flagged(tmp_path: Path) -> None:
    d = tmp_path / "onnx"
    d.mkdir()
    (d / "m.onnx").write_bytes(b"onnx-graph...\x0aPyOp\x0a...ai.onnx.contrib...")
    assert "M5" in {f.category for f in _scan(d).findings}


def test_onnx_external_traversal_is_flagged(tmp_path: Path) -> None:
    d = tmp_path / "onnx2"
    d.mkdir()
    (d / "m.onnx").write_bytes(b"...location...../../../etc/passwd...")
    assert "M6" in {f.category for f in _scan(d).findings}


# --------------------------------------------------------------------------- #
# GGUF is a safe format
# --------------------------------------------------------------------------- #


def test_gguf_is_treated_as_safe(tmp_path: Path) -> None:
    d = tmp_path / "gguf"
    d.mkdir()
    (d / "model.gguf").write_bytes(b"GGUF" + b"\x03\x00\x00\x00" + b"\x00" * 32)
    (d / "README.md").write_text("# model")
    (d / "sha256sums.txt").write_text("")
    result = _scan(d)
    # No pickle, and GGUF is safe → no M4 "risky format" advisory.
    assert "M4" not in {f.category for f in result.findings}


def test_gguf_alongside_pickle_suppresses_m4(tmp_path: Path) -> None:
    d = tmp_path / "mixed"
    d.mkdir()
    (d / "model.gguf").write_bytes(b"GGUF" + b"\x03\x00\x00\x00" + b"\x00" * 32)
    (d / "extra.pkl").write_bytes(pickle.dumps({"w": [1]}))
    result = _scan(d)
    # A safe format exists, so M4-pickle-without-safetensors should NOT fire.
    assert "M4-pickle-without-safetensors" not in {f.id for f in result.findings}
    assert DEFAULT_LIMITS.max_pickle_opcodes > 0
