"""Generate docs/demo.svg — a terminal-styled render of a real Airlock scan.

A self-contained SVG that GitHub renders inline, used as the README demo asset.
Run:  python scripts/gen_demo_svg.py
"""

from __future__ import annotations

from pathlib import Path

from bulwark_core.report.terminal import render_terminal
from rich.console import Console

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "docs" / "demo.svg"


def main() -> int:
    console = Console(record=True, width=100)
    result = ModelScanner(RuleEngine(load_rules())).scan(
        str(REPO_ROOT / "fixtures" / "model" / "poisoned")
    )
    render_terminal(result, console=console)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        console.export_svg(title="airlock scan model fixtures/model/poisoned"),
        encoding="utf-8",
    )
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
