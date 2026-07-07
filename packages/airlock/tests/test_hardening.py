"""Tests for scanner hardening: zip bombs, opcode caps, size caps, nested payloads."""

from __future__ import annotations

import base64
import pickle
import zipfile
from pathlib import Path

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner, pickle_scan
from airlock.scanners.model.loader import ArtifactFile
from bulwark_core.limits import Limits
from bulwark_core.signals import SignalBundle


def _artifact(path: Path) -> ArtifactFile:
    return ArtifactFile(
        path=path, relpath=path.name, size=path.stat().st_size, suffix=path.suffix.lower()
    )


class _ShellPayload:
    def __reduce__(self):  # type: ignore[no-untyped-def]
        import os

        return (os.system, ("echo AIRLOCK_SENTINEL",))


def _scan(dir_path: Path):
    return ModelScanner(RuleEngine(load_rules())).scan(str(dir_path))


# --------------------------------------------------------------------------- #
# Decompression bombs
# --------------------------------------------------------------------------- #


def test_zip_bomb_is_flagged(tmp_path: Path) -> None:
    d = tmp_path / "bomb"
    d.mkdir()
    pt = d / "model.pt"
    with zipfile.ZipFile(pt, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"w": [0]}))
        zf.writestr("archive/big.bin", b"\x00" * (3 * 1024 * 1024))  # 3 MiB of zeros
    (d / "config.json").write_text("{}")

    result = _scan(d)
    ids = {f.id for f in result.findings}
    assert "M6-decompression-bomb" in ids


def test_high_entropy_zip_is_not_a_bomb(tmp_path: Path) -> None:
    import os

    d = tmp_path / "ok"
    d.mkdir()
    pt = d / "model.pt"
    with zipfile.ZipFile(pt, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"w": [0]}))
        zf.writestr("archive/weights", os.urandom(512 * 1024))  # incompressible
    (d / "config.json").write_text("{}")

    result = _scan(d)
    assert "M6-decompression-bomb" not in {f.id for f in result.findings}


# --------------------------------------------------------------------------- #
# Opcode / size caps (anti-DoS)
# --------------------------------------------------------------------------- #


def test_opcode_cap_stops_without_crashing() -> None:
    blob = pickle.dumps(list(range(5000)))
    analysis = pickle_scan.analyze_stream(blob, Limits(max_pickle_opcodes=10))
    assert analysis.truncated is True
    assert analysis.error is None
    assert analysis.opcode_count <= 11


def test_oversized_zip_member_is_skipped(tmp_path: Path) -> None:
    pt = tmp_path / "model.pt"
    with zipfile.ZipFile(pt, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"w": list(range(50))}))
    out = pickle_scan.analyze_file(_artifact(pt), Limits(max_member_bytes=10))
    assert any(a.error and "size limit" in a.error for a in out.values())


# --------------------------------------------------------------------------- #
# Nested base64 payload recall
# --------------------------------------------------------------------------- #


def test_nested_base64_pickle_is_detected() -> None:
    inner = pickle.dumps(_ShellPayload())  # references os.system / nt.system
    outer = pickle.dumps({"blob": base64.b64encode(inner).decode()})
    analysis = pickle_scan.analyze_stream(outer)
    assert any(name.endswith(".system") for name in analysis.nested_imports)


def test_nested_payload_trips_m1_end_to_end(tmp_path: Path) -> None:
    d = tmp_path / "staged"
    d.mkdir()
    inner = pickle.dumps(_ShellPayload())
    (d / "weights.pkl").write_bytes(pickle.dumps({"blob": base64.b64encode(inner).decode()}))
    result = _scan(d)
    assert "M1" in {f.category for f in result.findings}


# --------------------------------------------------------------------------- #
# Malformed input must not crash
# --------------------------------------------------------------------------- #


def test_garbage_bytes_do_not_crash() -> None:
    bundle = SignalBundle(target="model")
    # A file that claims a pickle-ish suffix but is garbage.
    analysis = pickle_scan.analyze_stream(b"\x80\x04\xff\xff not a real pickle")
    assert analysis.error is not None or analysis.opcode_count >= 0
    assert isinstance(bundle.signals, list)
