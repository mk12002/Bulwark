"""Warden CLI smoke tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner
from warden.cli import app

runner = CliRunner()
FIX = Path(__file__).resolve().parents[1] / "fixtures"


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "warden" in result.stdout


def test_rules_list_and_lint() -> None:
    assert runner.invoke(app, ["rules", "list"]).exit_code == 0
    lint = runner.invoke(app, ["rules", "lint"])
    assert lint.exit_code == 0
    assert "validated" in lint.stdout


def test_import_prints_spec() -> None:
    result = runner.invoke(app, ["import", str(FIX / "over_privileged" / "basic.yaml")])
    assert result.exit_code == 0
    assert "devops-agent" in result.stdout


def test_audit_exfil_gates() -> None:
    result = runner.invoke(
        app, ["audit", str(FIX / "over_privileged" / "exfil.yaml"), "--format", "json"]
    )
    assert result.exit_code == 1  # A2/A5 at/above high
    assert '"A2"' in result.stdout


def test_audit_clean_exit_zero() -> None:
    result = runner.invoke(
        app, ["audit", str(FIX / "least_privilege" / "clean.yaml"), "--format", "json"]
    )
    assert result.exit_code == 0


def test_audit_recommend_prints_diff() -> None:
    result = runner.invoke(
        app, ["audit", str(FIX / "over_privileged" / "basic.yaml"), "--recommend", "--quiet"]
    )
    assert "Least-privilege recommendation" in result.stdout
    assert "sandbox" in result.stdout.lower()


def test_audit_sarif_format() -> None:
    result = runner.invoke(
        app, ["audit", str(FIX / "over_privileged" / "exfil.yaml"), "--format", "sarif"]
    )
    assert '"Warden"' in result.stdout  # tool-aware SARIF driver
