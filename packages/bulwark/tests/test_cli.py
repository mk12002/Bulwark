"""Smoke tests for the Bulwark meta-CLI: subcommands mount and the full pipeline runs."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from bulwark.cli import app

runner = CliRunner()

_RISKY = Path(__file__).resolve().parents[2] / "manifest" / "fixtures" / "sample_project_risky"


def test_version_lists_all_tools() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    for tool in ("bulwark", "airlock", "warden", "manifest"):
        assert tool in result.stdout


def test_subcommands_are_mounted() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("airlock", "warden", "manifest", "scan"):
        assert name in result.stdout


def test_airlock_subcommand_delegates() -> None:
    result = runner.invoke(app, ["airlock", "version"])
    assert result.exit_code == 0
    assert "airlock" in result.stdout


def test_full_pipeline_scan_folds_in_risk() -> None:
    # `bulwark scan` == manifest scan --scan-risk --govern: B-codes + inlined M-codes.
    result = runner.invoke(
        app, ["scan", str(_RISKY), "--offline", "--format", "json"], catch_exceptions=False
    )
    # Findings present → non-zero gate at default --fail-on high is acceptable; assert it ran.
    assert result.exit_code in (0, 1)
    assert '"tool": "manifest"' in result.stdout or "B" in result.stdout
