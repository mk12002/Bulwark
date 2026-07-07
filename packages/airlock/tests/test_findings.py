"""Tests for the core data model: Severity, Finding, ScanResult."""

from __future__ import annotations

from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.severity import Severity, parse_severity, worst_of


def _finding(sev: Severity, cat: str = "M1", fid: str = "x") -> Finding:
    return Finding(
        id=fid,
        category=cat,
        title="t",
        severity=sev,
        confidence="high",
        location=Location(target="model"),
        evidence="e",
        rationale="r",
        remediation="fix",
    )


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.INFO < Severity.CRITICAL
    assert worst_of([Severity.LOW, Severity.HIGH, Severity.MEDIUM]) == Severity.HIGH
    assert worst_of([]) == Severity.INFO


def test_parse_severity_case_insensitive() -> None:
    assert parse_severity("HIGH") == Severity.HIGH
    assert parse_severity("  critical ") == Severity.CRITICAL


def test_parse_severity_invalid() -> None:
    try:
        parse_severity("nope")
    except ValueError as exc:
        assert "unknown severity" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_scanresult_stats_and_worst() -> None:
    result = ScanResult(
        target="model",
        target_type="model",
        findings=[_finding(Severity.CRITICAL, "M1", "a"), _finding(Severity.LOW, "M7", "b")],
    )
    assert result.worst() == Severity.CRITICAL
    assert result.stats["critical"] == 1
    assert result.stats["low"] == 1
    assert result.stats["high"] == 0


def test_exit_code_threshold() -> None:
    result = ScanResult(
        target="model",
        target_type="model",
        findings=[_finding(Severity.MEDIUM)],
    )
    assert result.exit_code(Severity.HIGH) == 0
    assert result.exit_code(Severity.MEDIUM) == 1
    assert result.exit_code(Severity.LOW) == 1


def test_empty_result_is_clean() -> None:
    result = ScanResult(target="model", target_type="model", findings=[])
    assert result.worst() == Severity.INFO
    assert result.exit_code(Severity.INFO) == 0
    assert result.sorted_findings() == []


def test_sorted_findings_worst_first() -> None:
    result = ScanResult(
        target="model",
        target_type="model",
        findings=[_finding(Severity.LOW, "M7", "b"), _finding(Severity.CRITICAL, "M1", "a")],
    )
    order = [f.severity for f in result.sorted_findings()]
    assert order == [Severity.CRITICAL, Severity.LOW]
