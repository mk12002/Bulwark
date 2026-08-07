"""End-to-end audit tests against fixtures + the least-privilege recommendation."""

from __future__ import annotations

from pathlib import Path

import pytest
from bulwark_core.rules import RuleEngine
from bulwark_core.severity import Severity

from warden.recommend import recommend
from warden.rules import load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec


@pytest.fixture(scope="module")
def scanner() -> WardenScanner:
    return WardenScanner(RuleEngine(load_rules()))


def _cats(result) -> set[str]:
    return {f.category for f in result.findings}


def test_exfil_reports_a2_high_and_a5(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "exfil.yaml"))
    a2 = [f for f in result.findings if f.category == "A2"]
    assert a2 and a2[0].severity == Severity.HIGH
    assert "A5" in _cats(result)
    assert result.score is not None and result.score > 0
    assert result.exit_code(Severity.HIGH) == 1


def test_basic_over_privileged(scanner: WardenScanner, fixtures: Path) -> None:
    cats = _cats(scanner.scan(str(fixtures / "over_privileged" / "basic.yaml")))
    assert {"A1", "A3", "A8", "A10"} <= cats


def test_clean_control_is_clean(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "least_privilege" / "clean.yaml"))
    assert result.findings == []
    assert result.score == 0
    assert result.exit_code(Severity.HIGH) == 0


def test_mcp_client_reports_a9(scanner: WardenScanner, fixtures: Path) -> None:
    assert "A9" in _cats(scanner.scan(str(fixtures / "over_privileged" / "mcp_client.json")))


def test_import_error_degrades(scanner: WardenScanner, tmp_path: Path) -> None:
    bad = tmp_path / "x.json"
    bad.write_text('{"unrelated": 1}', encoding="utf-8")
    result = scanner.scan(str(bad))
    assert result.findings[0].id == "WARDEN-import-error"
    assert result.exit_code(Severity.HIGH) == 0


def test_meta_carries_agent_spec(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "basic.yaml"))
    assert result.meta.get("agent_spec", {}).get("name") == "devops-agent"
    assert result.meta.get("importer") == "manifest"


# --------------------------------------------------------------------------- #
# Recommendation
# --------------------------------------------------------------------------- #


def test_recommend_applies_hardening(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "basic.yaml"))
    spec = AgentSpec.model_validate(result.meta["agent_spec"])
    rec = recommend(spec)
    assert rec.changes  # something was hardened
    tool = rec.hardened.tools[0]
    assert tool.gate.value != "none"
    assert tool.sandboxed is True
    assert "*" not in tool.scopes


def test_hardened_spec_is_cleaner(scanner: WardenScanner, fixtures: Path) -> None:
    """Re-auditing the hardened spec should drop the gate/sandbox/scope findings."""
    result = scanner.scan(str(fixtures / "over_privileged" / "basic.yaml"))
    spec = AgentSpec.model_validate(result.meta["agent_spec"])
    hardened = recommend(spec).hardened
    reaudit = scanner.audit_spec(hardened, "hardened")
    before, after = _cats(result), _cats(reaudit)
    assert "A3" in before and "A3" not in after  # gate added
    assert "A8" in before and "A8" not in after  # sandbox added
    assert reaudit.score < (result.score or 0)
