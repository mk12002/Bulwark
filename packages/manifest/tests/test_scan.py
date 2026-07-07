"""End-to-end ManifestScanner + CLI tests."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.rules import RuleEngine
from bulwark_core.severity import Severity
from manifest.cli import app
from manifest.rules import load_rules
from manifest.scanner import ManifestScanner
from typer.testing import CliRunner

runner = CliRunner()


def _scanner(**kw) -> ManifestScanner:
    return ManifestScanner(RuleEngine(load_rules()), **kw)


def _cats(result) -> set[str]:
    return {f.category for f in result.findings}


def test_clean_project_is_clean(clean_project: Path) -> None:
    result = _scanner().scan(str(clean_project))
    assert result.findings == []
    assert result.exit_code(Severity.HIGH) == 0
    assert len(result.meta["aibom"]["components"]) >= 3


def test_risky_project_reports_governance_findings(risky_project: Path) -> None:
    cats = _cats(_scanner().scan(str(risky_project)))
    assert {"B1", "B3", "B4", "B6", "B7", "B8"} <= cats


def test_b4_severity_from_advisory(risky_project: Path) -> None:
    result = _scanner().scan(str(risky_project))
    b4 = [f for f in result.findings if f.category == "B4"]
    assert b4 and b4[0].severity == Severity.HIGH  # pyyaml CVE-2020-14343


def test_findings_attach_to_components(risky_project: Path) -> None:
    result = _scanner().scan(str(risky_project))
    comps = result.meta["aibom"]["components"]
    model = next(c for c in comps if c["type"] == "model" and c["license"]["risk"] == "restricted")
    assert any(fid.startswith("B3") for fid in model["findings"])


def test_scan_risk_bridge_imports_airlock(risky_project: Path) -> None:
    result = _scanner(scan_risk=True).scan(str(risky_project))
    cats = _cats(result)
    assert "B5" in cats  # roll-up
    assert any(c.startswith("M") for c in cats)  # Airlock's model findings surfaced inline


def test_govern_produces_assessment(risky_project: Path) -> None:
    result = _scanner(govern=True).scan(str(risky_project))
    assert "governance" in result.meta
    assert "risk_register" in result.meta
    assert "B9" in _cats(result)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_version_and_rules() -> None:
    assert runner.invoke(app, ["version"]).exit_code == 0
    assert runner.invoke(app, ["rules", "lint"]).exit_code == 0


def test_cli_scan_clean_exit_zero(clean_project: Path) -> None:
    result = runner.invoke(app, ["scan", str(clean_project), "--format", "json"])
    assert result.exit_code == 0


def test_cli_scan_risky_gates(risky_project: Path) -> None:
    result = runner.invoke(app, ["scan", str(risky_project), "--format", "json"])
    assert result.exit_code == 1  # B4/B7 are HIGH
    assert '"B4"' in result.stdout


def test_cli_cyclonedx_format(risky_project: Path) -> None:
    result = runner.invoke(app, ["scan", str(risky_project), "--format", "cyclonedx"])
    assert '"bomFormat": "CycloneDX"' in result.stdout


def test_cli_components(risky_project: Path) -> None:
    result = runner.invoke(app, ["components", str(risky_project)])
    assert result.exit_code == 0
    assert "pyyaml" in result.stdout
