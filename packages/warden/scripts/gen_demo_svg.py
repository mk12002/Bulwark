"""Generate docs/demo.svg — a terminal render of a real Warden audit.

Audits the injectable over-privileged fixture so the SVG shows the flagship output:
the CRITICAL attacker-triggerable kill chain plus the agency score. GitHub renders
the SVG inline as the README demo. Run:  python scripts/gen_demo_svg.py
"""

from __future__ import annotations

import io
from pathlib import Path

from bulwark_core.report.terminal import render_terminal
from bulwark_core.rules import RuleEngine
from rich.console import Console
from warden.rules import load_rules
from warden.scanner import WardenScanner

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = _ROOT / "fixtures" / "over_privileged" / "injectable.yaml"
_OUT = _ROOT / "docs" / "demo.svg"


def main() -> int:
    # Record into an in-memory buffer so we never write non-ASCII (→) to a cp1252 console.
    console = Console(record=True, width=100, file=io.StringIO())
    result = WardenScanner(RuleEngine(load_rules())).scan(str(_FIXTURE))
    render_terminal(result, console=console)
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(
        console.export_svg(title="warden audit web-research-agent.yaml"),
        encoding="utf-8",
    )
    print(f"wrote {_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
