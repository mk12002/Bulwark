"""HTML renderer: a single self-contained jinja2 report for sharing."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from bulwark_core.findings import ScanResult

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _environment() -> Environment:
    # autoescape is forced ON, not inferred from the file extension. The report
    # renders attacker-controlled strings (finding evidence, file paths, tool
    # descriptions from a hostile artifact) into HTML; without escaping, a crafted
    # model or MCP tool could inject <script>/onerror into the report an analyst
    # opens — a scanner-report XSS. The template is `report.html.j2`, whose `.j2`
    # suffix would have slipped past `select_autoescape(["html"])`.
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
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
