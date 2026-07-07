"""HTML renderer: a single self-contained jinja2 report for sharing."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from airlock.core.findings import ScanResult

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )


def render_html(result: ScanResult) -> str:
    """Render a scan result to a single HTML page."""
    env = _environment()
    template = env.get_template("report.html.j2")
    return template.render(
        result=result,
        findings=result.sorted_findings(),
        stats=result.stats,
        worst=result.worst().value,
    )
