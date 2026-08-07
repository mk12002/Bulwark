"""Tests for the framework importers (OpenAI Assistants, LangChain, CrewAI) + --scan-parts."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.findings import Finding, Location
from bulwark_core.severity import Severity

from warden.bridge import scan_wired_parts
from warden.importers import import_agent
from warden.spec.model import AgentSpec, Capability

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "frameworks"


def _caps(spec: AgentSpec) -> set[Capability]:
    return spec.all_capabilities()


def test_openai_assistant_import() -> None:
    spec, importer = import_agent(FIX / "openai_assistant.json")
    assert importer == "openai_assistant"
    assert spec.model == "gpt-4o"
    names = {t.name for t in spec.tools}
    assert {"code_interpreter", "file_search", "send_report"} <= names
    assert Capability.CODE_EXEC in _caps(spec)
    assert Capability.EMAIL_SEND in _caps(spec)
    # code_interpreter is declared sandboxed by the Assistants runtime.
    ci = next(t for t in spec.tools if t.name == "code_interpreter")
    assert ci.sandboxed is True


def test_langchain_import_static() -> None:
    spec, importer = import_agent(FIX / "langchain_agent.py")
    assert importer == "langchain"
    assert spec.model == "gpt-4o"
    assert spec.autonomy == "autonomous"  # AgentExecutor / create_react_agent
    names = {t.name for t in spec.tools}
    assert {"run_shell", "http_get"} <= names
    assert Capability.SHELL in _caps(spec)
    assert "access anything" in (spec.system_prompt or "")


def test_crewai_import() -> None:
    spec, importer = import_agent(FIX / "crewai_agents.yaml")
    assert importer == "crewai"
    assert spec.autonomy == "autonomous"  # allow_delegation
    names = {t.name for t in spec.tools}
    assert {"read_files", "post_webhook"} <= names


def test_framework_specs_flag_toxic_combination() -> None:
    """CrewAI fixture (read secrets + post webhook) should trip A2/A5 when audited."""
    from bulwark_core.rules import RuleEngine

    from warden.rules import load_rules
    from warden.scanner import WardenScanner

    scanner = WardenScanner(RuleEngine(load_rules()))
    cats = {f.category for f in scanner.scan(str(FIX / "crewai_agents.yaml")).findings}
    assert "A2" in cats


# --------------------------------------------------------------------------- #
# --scan-parts bridge
# --------------------------------------------------------------------------- #


def _fake_p_finding() -> Finding:
    return Finding(
        id="P4-shell-execution",
        category="P4",
        title="Tool exposes shell / command execution",
        severity=Severity.HIGH,
        confidence="high",
        location=Location(target="mcp", path="run_shell"),
        evidence="shell",
        rationale="r",
        remediation="fix",
    )


def test_scan_wired_parts_merges_airlock_findings() -> None:
    spec = AgentSpec(name="a", mcp_servers=["files: python server.py", "shell: python shell.py"])
    calls: list[str] = []

    def fake_run(command: str) -> list[Finding]:
        calls.append(command)
        return [_fake_p_finding()]

    findings = scan_wired_parts(spec, run_mcp=fake_run)
    assert len(calls) == 2  # both servers scanned
    assert all(f.category == "P4" for f in findings)


def test_scan_wired_parts_degrades_on_error() -> None:
    spec = AgentSpec(name="a", mcp_servers=["files: python server.py"])

    def boom(command: str) -> list[Finding]:
        raise RuntimeError("cannot spawn")

    assert scan_wired_parts(spec, run_mcp=boom) == []  # graceful


def test_scan_parts_flag_via_scanner() -> None:
    from bulwark_core.rules import RuleEngine

    from warden.rules import load_rules
    from warden.scanner import WardenScanner

    scanner = WardenScanner(RuleEngine(load_rules()), scan_parts=True)
    # An assembly with no wired MCP servers: scan_parts is a no-op, still clean elsewhere.
    result = scanner.scan(str(FIX / "openai_assistant.json"))
    assert isinstance(result.findings, list)
