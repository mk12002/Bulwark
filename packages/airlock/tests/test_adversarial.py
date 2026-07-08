"""Adversarial robustness: Airlock's *static* analysis must survive obfuscation.

Each fixture references ``os.system`` the way a real attack would but only ``echo``s an
inert marker, so nothing harmful runs even if a file were loaded (it never is). The
suite proves that protocol changes, ``STACK_GLOBAL`` (no classic ``GLOBAL`` opcode),
compression, base64 staging, ``.npy`` object arrays, and torch-style zips do not let a
malicious pickle slip past the scanner.

The evasive-corpus generator lives in ``scripts/adversarial.py`` (shared with the
picklescan benchmark); it is loaded here by path so the package itself ships no
pickle-generation code.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner

_GEN_PATH = Path(__file__).resolve().parents[1] / "scripts" / "adversarial.py"


def _load_generator():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("airlock_adversarial", _GEN_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan_one(engine: RuleEngine, name: str, path: Path) -> set[str]:
    # Isolate each artifact in its own directory so findings are unambiguous.
    sub = path.parent / f"_{name}"
    sub.mkdir(exist_ok=True)
    (sub / path.name).write_bytes(path.read_bytes())
    result = ModelScanner(engine).scan(str(sub))
    return {f.category for f in result.findings}


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> list[tuple[str, Path]]:
    gen = _load_generator()
    return gen.build_adversarial_corpus(tmp_path_factory.mktemp("adversarial"))  # type: ignore[no-any-return]


def test_generator_produces_a_spread(corpus: list[tuple[str, Path]]) -> None:
    names = {n for n, _ in corpus}
    # protocols 0-5 plus the key evasion families must all be present.
    assert {f"reduce_proto{i}" for i in range(6)} <= names
    assert {
        "stack_global",
        "stack_global_framed",
        "gzip_bin",
        "zlib_bin",
        "base64_nested",
        "npy_object",
        "torch_zip",
        "disguised_safetensors",
    } <= names


def test_every_evasive_pickle_trips_code_execution(corpus: list[tuple[str, Path]]) -> None:
    engine = RuleEngine(load_rules())
    misses: list[str] = []
    for name, path in corpus:
        cats = _scan_one(engine, name, path)
        if "M1" not in cats:
            misses.append(name)
    assert not misses, f"static analysis missed code-execution on: {misses}"


def test_stack_global_has_no_classic_global_string(corpus: list[tuple[str, Path]]) -> None:
    # The whole point: no 'c os\nsystem' substring, yet Airlock still flags it.
    path = next(p for n, p in corpus if n == "stack_global")
    assert b"c os\nsystem" not in path.read_bytes()
    engine = RuleEngine(load_rules())
    assert "M1" in _scan_one(engine, "stack_global", path)


def test_pickle_disguised_as_safetensors_trips_mismatch(corpus: list[tuple[str, Path]]) -> None:
    # Extension spoofing (CVE-2025-10155 class): a pickle named .safetensors must be
    # flagged for the deception (M6) AND scanned as a pickle (M1).
    path = next(p for n, p in corpus if n == "disguised_safetensors")
    engine = RuleEngine(load_rules())
    result = ModelScanner(engine).scan(str(path.parent))
    ids = {f.id for f in result.findings}
    cats = {f.category for f in result.findings}
    assert "M6-format-extension-mismatch" in ids
    assert "M1" in cats


class _NovelImport:
    """Imports from a module a denylist may not know — caught only by the allowlist."""

    def __reduce__(self):  # type: ignore[no-untyped-def]
        import socket

        return (socket.gethostname, ())


def test_allowlist_mode_flags_unexpected_module(tmp_path: Path) -> None:
    import pickle

    (tmp_path / "m.bin").write_bytes(pickle.dumps(_NovelImport(), protocol=4))
    engine = RuleEngine(load_rules())

    default = ModelScanner(engine).scan(str(tmp_path))
    strict = ModelScanner(engine, strict=True).scan(str(tmp_path))

    # Default (non-strict) mode does not raise the allowlist finding...
    assert not any(f.id == "M3-unexpected-pickle-import" for f in default.findings)
    # ...but strict mode surfaces the unexpected import.
    assert any(f.id == "M3-unexpected-pickle-import" for f in strict.findings)


def test_allowlist_mode_no_false_positive_on_torch_imports(tmp_path: Path) -> None:
    # A pickle importing only collections.OrderedDict (allowlisted) must stay clean.
    import pickle

    (tmp_path / "m.bin").write_bytes(pickle.dumps({"a": 1}, protocol=4))
    engine = RuleEngine(load_rules())
    strict = ModelScanner(engine, strict=True).scan(str(tmp_path))
    assert not any(f.id == "M3-unexpected-pickle-import" for f in strict.findings)


def test_real_safetensors_is_not_flagged_as_mismatch(tmp_path: Path) -> None:
    # A genuine safetensors file (8-byte LE header length + JSON header) must NOT
    # trip the format-confusion detector — no false positives.
    import json
    import struct

    header = json.dumps({"__metadata__": {"format": "pt"}}).encode()
    blob = struct.pack("<Q", len(header)) + header + b"\x00" * 32
    (tmp_path / "weights.safetensors").write_bytes(blob)
    engine = RuleEngine(load_rules())
    result = ModelScanner(engine).scan(str(tmp_path))
    assert not any(f.id == "M6-format-extension-mismatch" for f in result.findings)
