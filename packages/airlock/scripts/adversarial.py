"""Generate a benign-but-*evasive* pickle corpus for robustness testing.

Every artifact here references a dangerous callable (``os.system``) the way a real
attack would, but the only argument is an inert ``echo`` of a marker string — so
disassembly-based scanners must flag it, yet nothing harmful happens even if a file
were (accidentally) loaded. These probe whether Airlock's *static* analysis survives
obfuscation that trips naive string-grep scanners:

- multiple pickle **protocols** (0-5) and **framed** pickles (proto 4+),
- ``STACK_GLOBAL`` instead of the classic ``GLOBAL`` opcode (no ``c os\\nsystem`` string),
- **gzip/zlib-compressed** pickles wearing a ``.bin`` model extension,
- a **base64-nested** payload (staged one level deep),
- an object-dtype **.npy** hiding a pickle,
- a **torch-style zip** (pickle as an inner archive member).

Nothing is ever unpickled. Used by ``tests/test_adversarial.py`` and the picklescan
benchmark (``scripts/benchmark.py``).
"""

from __future__ import annotations

import base64
import gzip
import pickle
import struct
import zipfile
import zlib
from pathlib import Path

MARKER = "echo airlock-benign-marker"


class _Reduce:
    """Benign reduce payload: os.system('echo ...'). Never executed by the scanner."""

    def __reduce__(self):  # type: ignore[no-untyped-def]
        import os

        return (os.system, (MARKER,))


def _stack_global_pickle(proto: int, *, framed: bool = False) -> bytes:
    """Hand-assemble os.system(MARKER) using STACK_GLOBAL (no classic GLOBAL opcode)."""

    def su(s: str) -> bytes:  # SHORT_BINUNICODE
        b = s.encode()
        return b"\x8c" + bytes([len(b)]) + b

    body = su("os") + su("system") + b"\x93"  # STACK_GLOBAL -> os.system
    body += su(MARKER) + b"\x85" + b"R"  # (MARKER,) then REDUCE
    body += b"."  # STOP
    head = b"\x80" + bytes([proto]) if proto >= 2 else b""
    if framed and proto >= 4:
        frame = b"\x95" + struct.pack("<Q", len(body))
        return head + frame + body
    return head + body


def _npy_object(payload: bytes) -> bytes:
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header = header + " " * ((64 - (10 + len(header) + 1) % 64) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode("latin1") + payload


def build_adversarial_corpus(dest: Path) -> list[tuple[str, Path]]:
    """Write every evasive variant into ``dest``; return ``[(variant_name, path), ...]``."""
    dest.mkdir(parents=True, exist_ok=True)
    out: list[tuple[str, Path]] = []

    def write(name: str, filename: str, data: bytes) -> None:
        p = dest / filename
        p.write_bytes(data)
        out.append((name, p))

    # 1. Every protocol via the normal reduce path.
    for proto in range(6):
        blob = pickle.dumps(_Reduce(), protocol=proto)
        write(f"reduce_proto{proto}", f"reduce_p{proto}.pkl", blob)

    # 2. STACK_GLOBAL-based (no 'c os\nsystem' substring) + framed.
    write("stack_global", "stack_global.pkl", _stack_global_pickle(4))
    write("stack_global_framed", "framed.pkl", _stack_global_pickle(5, framed=True))

    # 3. Compressed pickles wearing a model extension.
    raw = pickle.dumps(_Reduce(), protocol=4)
    write("gzip_bin", "gzipped_model.bin", gzip.compress(raw))
    write("zlib_bin", "zlib_model.bin", zlib.compress(raw))

    # 4. Base64-nested: a pickle whose (string) payload decodes to another dangerous
    #    pickle — the classic "staged" layout, embedded as a str constant like real payloads.
    nested = base64.b64encode(raw).decode("ascii")
    write("base64_nested", "nested.pkl", pickle.dumps(nested, protocol=4))

    # 5. Object-dtype .npy hiding a pickle.
    write("npy_object", "weights.npy", _npy_object(raw))

    # 6. Torch-style zip: pickle as an inner archive member.
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", raw)
    write("torch_zip", "model.pt", buf.getvalue())

    return out


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("datasets/adversarial")
    items = build_adversarial_corpus(target)
    print(f"wrote {len(items)} evasive artifacts to {target}")
    for name, path in items:
        print(f"  {name:22} {path.name}")
