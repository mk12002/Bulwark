"""Benchmark Airlock against other open pickle scanners on the evasive corpus + real models.

For every pickle-bearing artifact we ask each scanner the same question:
    do you flag *code execution* (a dangerous callable / unsafe pickle)?

- **Airlock**    — any `M1` finding.
- **picklescan** — any Dangerous global or non-zero issue count.
- **modelscan**  — any issue reported by `ModelScan().scan()`.
- **fickling**   — `check_safety()` severity at or above `LIKELY_UNSAFE`.

The comparison is deliberately honest: it prints exactly where tools agree and differ, never hides
an Airlock miss, and reports `n/a` when a tool cannot process an input (fickling does not handle
zip-wrapped pickles). Missing tools are simply omitted, so this runs with whatever is installed.

Usage (from repo root, venv active):
    pip install picklescan modelscan fickling      # optional competitors
    python packages/airlock/scripts/benchmark.py                      # adversarial only
    python packages/airlock/scripts/benchmark.py datasets/corpus.txt  # + real models
    python packages/airlock/scripts/benchmark.py datasets/corpus.txt > out.md
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT / "packages" / "airlock" / "scripts"))
from adversarial import build_adversarial_corpus  # noqa: E402

PICKLE_SUFFIXES = {".pkl", ".bin", ".pt", ".pth", ".ckpt", ".npy"}

# A verdict is True (flagged exec), False (scanned, clean), or None (couldn't process / absent).
Verdict = bool | None
Scanner = Callable[[Path], Verdict]


def _airlock_scanner() -> Scanner:
    """Airlock scans the file in place (the loader accepts a single file), writing nothing."""
    engine = RuleEngine(load_rules())

    def scan(path: Path) -> Verdict:
        result = ModelScanner(engine).scan(str(path))
        return any(f.category == "M1" for f in result.findings)

    return scan


def _picklescan_scanner() -> Scanner | None:
    try:
        from picklescan.scanner import SafetyLevel, scan_file_path
    except ImportError:
        return None

    def scan(path: Path) -> Verdict:
        try:
            res = scan_file_path(str(path))
        except Exception:
            return None
        if getattr(res, "scan_err", False):
            return None
        dangerous = any(g.safety == SafetyLevel.Dangerous for g in res.globals)
        return bool(res.issues_count) or dangerous

    return scan


def _modelscan_scanner() -> Scanner | None:
    try:
        from modelscan.modelscan import ModelScan
    except ImportError:
        return None

    def scan(path: Path) -> Verdict:
        try:
            report = ModelScan().scan(str(path))
        except Exception:
            return None
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        total = summary.get("total_issues")
        return None if total is None else bool(total)

    return scan


def _fickling_scanner() -> Scanner | None:
    try:
        from fickling.analysis import Severity, check_safety
        from fickling.fickle import Pickled
    except ImportError:
        return None

    # "Flags code execution" = severity at or above LIKELY_UNSAFE (generous to fickling; it also
    # emits weaker SUSPICIOUS/POSSIBLY_UNSAFE levels we do not count as a hard exec flag).
    threshold = list(Severity).index(Severity.LIKELY_UNSAFE)

    def scan(path: Path) -> Verdict:
        try:
            result = check_safety(Pickled.load(path.read_bytes()))
        except Exception:
            return None  # fickling does not handle zip-wrapped pickles, etc.
        return list(Severity).index(result.severity) >= threshold

    return scan


def build_scanners() -> dict[str, Scanner]:
    """Return every available scanner, keyed by name (missing competitors are omitted)."""
    candidates: list[tuple[str, Scanner | None]] = [
        ("Airlock", _airlock_scanner()),
        ("picklescan", _picklescan_scanner()),
        ("modelscan", _modelscan_scanner()),
        ("fickling", _fickling_scanner()),
    ]
    return {name: fn for name, fn in candidates if fn is not None}


def _iter_corpus_pickles(manifest: Path) -> list[tuple[str, Path]]:
    """Yield (label, path) for pickle files referenced by a study manifest."""
    out: list[tuple[str, Path]] = []
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or not line.startswith("model "):
            continue
        d = Path(line.split(" ", 1)[1])
        if not d.exists():
            continue
        for f in sorted(d.rglob("*")):
            if ".cache" in f.parts:  # skip the HuggingFace download cache
                continue
            if f.is_file() and f.suffix.lower() in PICKLE_SUFFIXES:
                out.append((f"{d.name}/{f.name}", f))
    return out


Row = tuple[str, dict[str, Verdict]]


def run(manifest: Path | None) -> tuple[list[str], dict[str, list[Row]]]:
    scanners = build_scanners()
    names = list(scanners)
    adv_dir = Path(_ROOT) / "datasets" / "_benchmark_adv"
    groups: dict[str, list[Row]] = {"adversarial": [], "real-models": []}

    for label, path in build_adversarial_corpus(adv_dir):
        groups["adversarial"].append((label, {n: scanners[n](path) for n in names}))
    if manifest and manifest.exists():
        for label, path in _iter_corpus_pickles(manifest):
            groups["real-models"].append((label, {n: scanners[n](path) for n in names}))
    return names, groups


def _fmt(v: Verdict) -> str:
    return "flag" if v is True else ("miss" if v is False else "n/a")


def render_markdown(names: list[str], groups: dict[str, list[Row]]) -> str:
    lines = [
        "# Airlock vs. open pickle scanners",
        "",
        f"Code-execution detection on pickle artifacts. Scanners compared: {', '.join(names)}.",
        "",
    ]
    for group, rows in groups.items():
        if not rows:
            continue
        lines += [f"## {group} ({len(rows)} artifacts)", ""]
        for n in names:
            hits = sum(1 for _, v in rows if v[n] is True)
            lines.append(f"- {n} flagged code execution: **{hits}/{len(rows)}**")
        lines += ["", "| Artifact | " + " | ".join(names) + " |"]
        lines.append("| --- | " + " | ".join([":---:"] * len(names)) + " |")
        for label, verdicts in rows:
            lines.append(f"| {label} | " + " | ".join(_fmt(verdicts[n]) for n in names) + " |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    manifest = Path(args[0]) if args else None
    names, groups = run(manifest)
    print(render_markdown(names, groups))
    return 0


if __name__ == "__main__":
    sys.exit(main())
