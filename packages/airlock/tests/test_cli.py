"""CLI smoke tests via typer's CliRunner."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.cli import app

runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_rules_list() -> None:
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == 0
    assert "rule(s) loaded" in result.stdout
    assert "M1" in result.stdout


def test_rules_lint_ok() -> None:
    result = runner.invoke(app, ["rules", "lint"])
    assert result.exit_code == 0
    assert "validated" in result.stdout


def test_scan_model_poisoned_exit_nonzero() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "poisoned")
    result = runner.invoke(app, ["scan", "model", target, "--format", "json"])
    assert result.exit_code == 1  # critical >= high threshold
    assert '"M1"' in result.stdout


def test_scan_model_clean_exit_zero() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "clean")
    result = runner.invoke(app, ["scan", "model", target, "--format", "json"])
    assert result.exit_code == 0


def test_scan_model_fail_on_low() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "clean")
    result = runner.invoke(app, ["scan", "model", target, "--format", "json", "--fail-on", "low"])
    assert result.exit_code == 0  # clean has zero findings at any threshold


def test_scan_model_fail_on_critical_gates() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "poisoned")
    result = runner.invoke(
        app, ["scan", "model", target, "--format", "json", "--fail-on", "critical"]
    )
    assert result.exit_code == 1  # poisoned has a CRITICAL M1


def test_scan_model_invalid_fail_on() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "clean")
    result = runner.invoke(app, ["scan", "model", target, "--fail-on", "bogus"])
    assert result.exit_code == 2  # usage error, not a scan gate


def test_scan_model_sarif_format() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "poisoned")
    result = runner.invoke(app, ["scan", "model", target, "--format", "sarif"])
    assert result.exit_code == 1  # findings gate at default --fail-on high
    assert '"version": "2.1.0"' in result.stdout
    assert '"ruleId": "M1"' in result.stdout


def test_scan_model_html_format() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "poisoned")
    result = runner.invoke(app, ["scan", "model", target, "--format", "html"])
    assert "<!doctype html>" in result.stdout.lower()
    assert "M1" in result.stdout


def test_scan_model_unknown_format_errors() -> None:
    target = str(REPO_ROOT / "fixtures" / "model" / "clean")
    result = runner.invoke(app, ["scan", "model", target, "--format", "xml"])
    assert result.exit_code == 2  # clean usage error, not a crash


def test_scan_model_ai_flag_degrades_without_config(monkeypatch: pytest.MonkeyPatch) -> None:
    # With AI disabled (the default), --ai must degrade to deterministic-only, not crash.
    monkeypatch.delenv("AIRLOCK_AI__ENABLED", raising=False)
    target = str(REPO_ROOT / "fixtures" / "model" / "clean")
    result = runner.invoke(app, ["scan", "model", target, "--format", "json", "--ai"])
    assert result.exit_code == 0
    assert '"findings"' in result.stdout  # deterministic result still rendered
