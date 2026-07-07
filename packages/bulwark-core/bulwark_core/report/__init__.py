"""Report renderers: terminal (rich), JSON, HTML, SARIF."""

from __future__ import annotations

from bulwark_core.findings import ScanResult
from bulwark_core.report.json_report import render_json
from bulwark_core.report.terminal import render_terminal

__all__ = ["render_json", "render_report", "render_terminal"]


def render_report(result: ScanResult, fmt: str, *, quiet: bool = False) -> str:
    """Render a scan result to a string in the requested format.

    Terminal output is written straight to the console by :func:`render_terminal`
    and returns an empty string; the other formats return their serialized text.
    """
    fmt = fmt.lower()
    if fmt == "terminal":
        render_terminal(result, quiet=quiet)
        return ""
    if fmt == "json":
        return render_json(result)
    if fmt == "html":
        from bulwark_core.report.html import render_html

        return render_html(result)
    if fmt == "sarif":
        from bulwark_core.report.sarif import render_sarif

        return render_sarif(result)
    raise ValueError(f"unknown output format {fmt!r}; expected terminal|json|html|sarif")
