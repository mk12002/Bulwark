"""Tests for waiver suppression and baseline diffing."""

from __future__ import annotations

from pathlib import Path

from airlock.core.findings import Finding, Location, ScanResult
from airlock.core.postprocess import apply_baseline, apply_waivers
from airlock.core.report.json_report import render_json
from airlock.core.severity import Severity


def _f(fid: str, cat: str, path: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=fid,
        category=cat,
        title="t",
        severity=sev,
        confidence="high",
        location=Location(target="model", path=path),
        evidence="e",
        rationale="r",
        remediation="fix",
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(target="t", target_type="model", findings=findings)


def test_waiver_by_rule_glob() -> None:
    r = _result([_f("M4-pickle-without-safetensors", "M4", "a.bin"), _f("M1-x", "M1", "a.bin")])
    out = apply_waivers(r, ["M4-*"], [])
    assert {f.id for f in out.findings} == {"M1-x"}
    assert out.suppressed == 1
    assert out.stats["medium"] == 0  # stats recomputed after suppression


def test_waiver_by_path_glob() -> None:
    r = _result([_f("M1-x", "M1", "vendor/model.bin"), _f("M1-y", "M1", "app/model.bin")])
    out = apply_waivers(r, [], ["vendor/*"])
    assert {f.id for f in out.findings} == {"M1-y"}
    assert out.suppressed == 1


def test_waiver_no_op_returns_same() -> None:
    r = _result([_f("M1-x", "M1", "a.bin")])
    assert apply_waivers(r, [], []) is r


def test_baseline_reports_only_new(tmp_path: Path) -> None:
    old = _result([_f("M1-x", "M1", "a.bin")])
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(render_json(old), encoding="utf-8")

    new = _result([_f("M1-x", "M1", "a.bin"), _f("M5-y", "M5", "config.json")])
    out = apply_baseline(new, baseline_file)
    assert {f.id for f in out.findings} == {"M5-y"}  # only the regression
    assert out.suppressed == 1


def test_baseline_all_known_is_clean(tmp_path: Path) -> None:
    old = _result([_f("M1-x", "M1", "a.bin")])
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(render_json(old), encoding="utf-8")
    out = apply_baseline(_result([_f("M1-x", "M1", "a.bin")]), baseline_file)
    assert out.findings == []
    assert out.exit_code(Severity.HIGH) == 0  # no regressions => gate passes
