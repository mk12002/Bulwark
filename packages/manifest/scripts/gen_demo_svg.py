"""Generate docs/demo.svg — a terminal render of a real Manifest scan.

Runs `manifest scan --scan-risk --govern` over the risky sample project so the SVG
shows the aggregator in action: B-code governance findings with Airlock's model
risk folded in. GitHub renders the SVG inline as the README demo.
Run:  python scripts/gen_demo_svg.py
"""

from __future__ import annotations

import io
from pathlib import Path

from bulwark_core.report.terminal import render_terminal
from bulwark_core.rules import RuleEngine
from manifest.rules import load_rules
from manifest.scanner import ManifestScanner
from rich.console import Console

_ROOT = Path(__file__).resolve().parents[1]
_PROJECT = _ROOT / "fixtures" / "sample_project_risky"
_OUT = _ROOT / "docs" / "demo.svg"


def main() -> int:
    # Record into an in-memory buffer so we never write non-ASCII to a cp1252 console.
    console = Console(record=True, width=100, file=io.StringIO())
    scanner = ManifestScanner(RuleEngine(load_rules()), offline=True, scan_risk=True, govern=True)
    result = scanner.scan(str(_PROJECT))
    render_terminal(result, console=console)
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(
        console.export_svg(title="manifest scan ./project --scan-risk --govern"),
        encoding="utf-8",
    )
    print(f"wrote {_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
