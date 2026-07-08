"""Generate docs/demo_suite.svg — a terminal render of the full `bulwark scan` pipeline.

Runs Manifest with the Airlock/Warden risk bridges over the risky sample project, so the
SVG shows the suite's thesis: an AI-BOM with model/agent findings folded in. GitHub renders
the SVG inline as the README hero. Run:  python packages/bulwark/scripts/gen_demo_svg.py
"""

from __future__ import annotations

from pathlib import Path

from bulwark_core.report.terminal import render_terminal
from bulwark_core.rules import RuleEngine
from manifest.rules import load_rules
from manifest.scanner import ManifestScanner
from rich.console import Console

_ROOT = Path(__file__).resolve().parents[3]
_PROJECT = _ROOT / "packages" / "manifest" / "fixtures" / "sample_project_risky"
_OUT = _ROOT / "docs" / "demo_suite.svg"


def main() -> int:
    console = Console(record=True, width=100)
    scanner = ManifestScanner(RuleEngine(load_rules()), offline=True, scan_risk=True, govern=True)
    result = scanner.scan(str(_PROJECT))
    render_terminal(result, console=console)
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(
        console.export_svg(title="bulwark scan ./project --scan-risk --govern"),
        encoding="utf-8",
    )
    print(f"wrote {_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
