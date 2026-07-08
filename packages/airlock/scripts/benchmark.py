"""Benchmark Airlock against picklescan on the evasive corpus + real models.

For every pickle-bearing artifact we ask two questions of each scanner:
    does it flag *code execution* (a dangerous callable)?
Airlock's answer is "any M1 finding"; picklescan's is "any Dangerous global / issue".

The interesting rows are the evasive variants: both tools disassemble, so both should
catch most, but the comparison is honest — it prints exactly where they agree and
differ, and never hides an Airlock miss.

Usage (from repo root, venv active):
    python packages/airlock/scripts/benchmark.py                 # adversarial only
    python packages/airlock/scripts/benchmark.py datasets/corpus.txt   # + real models
    python packages/airlock/scripts/benchmark.py --md > docs/BENCHMARK.md
"""

from __future__ import annotations

import sys
from pathlib import Path

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT / "packages" / "airlock" / "scripts"))
from adversarial import build_adversarial_corpus  # noqa: E402

PICKLE_SUFFIXES = {".pkl", ".bin", ".pt", ".pth", ".ckpt", ".npy"}


def airlock_flags_exec(engine: RuleEngine, path: Path) -> bool:
    """True if Airlock reports M1 (code execution) for the artifact at ``path``.

    Scans the file in place — the loader accepts a single file — so the benchmark
    never writes anything into the corpus (an earlier version copied files into each
    model directory and silently inflated repeated runs).
    """
    result = ModelScanner(engine).scan(str(path))
    return any(f.category == "M1" for f in result.findings)


def picklescan_flags_exec(path: Path) -> bool | None:
    """True/False from picklescan; None if it errors or isn't installed."""
    try:
        from picklescan.scanner import SafetyLevel, scan_file_path
    except ImportError:
        return None
    try:
        res = scan_file_path(str(path))
    except Exception:
        return None
    if getattr(res, "scan_err", False):
        return None
    dangerous = any(g.safety == SafetyLevel.Dangerous for g in res.globals)
    return bool(res.issues_count) or dangerous


def _iter_corpus_pickles(manifest: Path) -> list[tuple[str, Path]]:
    """Yield (label, path) for pickle files referenced by a study manifest."""
    out: list[tuple[str, Path]] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or not line.startswith("model "):
            continue
        d = Path(line.split(" ", 1)[1])
        if not d.exists():
            continue
        for f in sorted(d.rglob("*")):
            # Skip the HuggingFace download cache; scan only real artifact files.
            if ".cache" in f.parts:
                continue
            if f.is_file() and f.suffix.lower() in PICKLE_SUFFIXES:
                out.append((f"{d.name}/{f.name}", f))
    return out


def run(manifest: Path | None) -> dict[str, list[tuple[str, bool, bool | None]]]:
    engine = RuleEngine(load_rules())
    adv_dir = Path(_ROOT) / "datasets" / "_benchmark_adv"
    groups: dict[str, list[tuple[str, bool, bool | None]]] = {"adversarial": [], "real-models": []}

    for name, path in build_adversarial_corpus(adv_dir):
        groups["adversarial"].append(
            (name, airlock_flags_exec(engine, path), picklescan_flags_exec(path))
        )
    if manifest and manifest.exists():
        for label, path in _iter_corpus_pickles(manifest):
            groups["real-models"].append(
                (label, airlock_flags_exec(engine, path), picklescan_flags_exec(path))
            )
    return groups


def _fmt(v: bool | None) -> str:
    return "flag" if v is True else ("miss" if v is False else "n/a")


def render_markdown(groups: dict[str, list[tuple[str, bool, bool | None]]]) -> str:
    lines = ["# Airlock vs. picklescan", "", "Code-execution detection on pickle artifacts.", ""]
    for group, rows in groups.items():
        if not rows:
            continue
        a_hit = sum(1 for _, a, _ in rows if a)
        p_hit = sum(1 for _, _, p in rows if p)
        lines += [
            f"## {group} ({len(rows)} artifacts)",
            "",
            f"- Airlock flagged code execution: **{a_hit}/{len(rows)}**",
            f"- picklescan flagged code execution: **{p_hit}/{len(rows)}**",
            "",
            "| Artifact | Airlock | picklescan |",
            "| --- | :---: | :---: |",
        ]
        for name, a, p in rows:
            lines.append(f"| {name} | {_fmt(a)} | {_fmt(p)} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--md"]
    manifest = Path(args[0]) if args else None
    groups = run(manifest)
    print(render_markdown(groups))
    return 0


if __name__ == "__main__":
    sys.exit(main())
