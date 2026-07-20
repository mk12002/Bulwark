"""Tests for JSON, SARIF, HTML, and terminal renderers."""

from __future__ import annotations

import json

from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.report import render_report
from bulwark_core.report.sarif import render_sarif
from bulwark_core.report.terminal import render_terminal
from bulwark_core.severity import Severity
from rich.console import Console


def _result() -> ScanResult:
    return ScanResult(
        target="fixtures/model/poisoned",
        target_type="model",
        tool="airlock",
        findings=[
            Finding(
                id="M1-pickle-shell-exec",
                category="M1",
                title="Pickle references a shell/exec/eval callable",
                severity=Severity.CRITICAL,
                confidence="high",
                location=Location(target="model", path="pytorch_model.bin", detail="opcode@42"),
                evidence="os.system",
                rationale="rce",
                remediation="do not load",
                references=["OWASP:LLM05", "CWE-502"],
            )
        ],
    )


def test_json_roundtrips() -> None:
    text = render_report(_result(), "json")
    data = json.loads(text)
    assert data["target_type"] == "model"
    assert data["findings"][0]["category"] == "M1"
    assert data["findings"][0]["severity"] == "critical"
    assert data["stats"]["critical"] == 1


def test_sarif_shape() -> None:
    data = json.loads(render_sarif(_result()))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Airlock"
    result = run["results"][0]
    assert result["ruleId"] == "M1"
    assert result["level"] == "error"  # critical -> error
    assert result["properties"]["ruleInstanceId"] == "M1-pickle-shell-exec"


def test_sarif_rule_descriptors_unique() -> None:
    data = json.loads(render_sarif(_result()))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids == ["M1"]


def test_html_contains_finding() -> None:
    html = render_report(_result(), "html")
    assert "M1" in html
    assert "os.system" in html
    assert "<!doctype html>" in html.lower()


def test_html_report_escapes_hostile_strings() -> None:
    # The report renders attacker-controlled strings from a hostile artifact. They
    # must be HTML-escaped, or opening a report becomes a scanner-report XSS.
    result = ScanResult(
        target="<svg onload=alert(1)>",
        target_type="model",
        tool="airlock",
        findings=[
            Finding(
                id="M1",
                category="M1",
                title="t",
                severity=Severity.CRITICAL,
                confidence="high",
                location=Location(target="x", path="<script>alert(1)</script>.bin"),
                evidence="<img src=x onerror=alert(document.domain)>",
                rationale="r",
                remediation="rm",
            )
        ],
    )
    html = render_report(result, "html")
    # No raw executable markup from the artifact survives into the report.
    assert "<script" not in html
    assert "<img" not in html
    assert "<svg" not in html
    # It is present, but escaped.
    assert "&lt;script&gt;" in html


def test_terminal_renders_without_error() -> None:
    console = Console(record=True, width=120)
    render_terminal(_result(), console=console)
    text = console.export_text()
    assert "CRITICAL" in text
    assert "M1" in text


def test_terminal_clean() -> None:
    console = Console(record=True, width=120)
    render_terminal(ScanResult(target="x", target_type="model", findings=[]), console=console)
    assert "clean" in console.export_text().lower()


def test_unknown_format_raises() -> None:
    try:
        render_report(_result(), "xml")
    except ValueError as exc:
        assert "unknown output format" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")
