"""Agent discovery (Agent BOM) + VEX output."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.rules import RuleEngine

from manifest.bom.cyclonedx import to_cyclonedx
from manifest.bom.model import AIBOM, Component, ComponentType
from manifest.bom.vex import to_vex
from manifest.discover import discover_project
from manifest.rules import load_rules
from manifest.scanner import ManifestScanner

_AGENT_YAML = """\
name: support-agent
model: gpt-4o
autonomy: autonomous
system_prompt: "You help customers."
tools:
  - name: read_tickets
  - name: send_email
"""


def _write_agent_project(tmp_path: Path) -> Path:
    (tmp_path / "agent.yaml").write_text(_AGENT_YAML, encoding="utf-8")
    return tmp_path


def test_agent_discovered_as_component(tmp_path: Path) -> None:
    bom = discover_project(_write_agent_project(tmp_path))
    agents = [c for c in bom.components if c.type is ComponentType.AGENT]
    assert len(agents) == 1
    agent = agents[0]
    assert agent.name == "support-agent"
    assert agent.metadata["autonomy"] == "autonomous"
    assert agent.metadata["tool_count"] == 2
    assert "send_email" in agent.metadata["tools"]


def test_agent_component_emits_agent_bom_properties() -> None:
    bom = AIBOM(project="p")
    bom.add(
        Component(
            key="agent:a",
            type=ComponentType.AGENT,
            name="a",
            metadata={
                "framework": "manifest",
                "autonomy": "autonomous",
                "model": "gpt-4o",
                "tools": ["t1", "t2"],
                "tool_count": 2,
            },
        )
    )
    cdx = to_cyclonedx(bom)
    props = {(p["name"], p["value"]) for c in cdx["components"] for p in c.get("properties", [])}
    assert ("bulwark:agent:autonomy", "autonomous") in props
    assert ("bulwark:agent:model", "gpt-4o") in props
    assert ("bulwark:agent:tool", "t1") in props
    assert ("bulwark:agent:tool-count", "2") in props


def test_vex_lists_known_vulnerabilities(risky_project: Path) -> None:
    scanner = ManifestScanner(RuleEngine(load_rules()), offline=True)
    result = scanner.scan(str(risky_project))
    vex = to_vex(result)
    assert vex["bomFormat"] == "CycloneDX"
    vulns = vex["vulnerabilities"]
    assert vulns, "risky project should have at least one B4 dependency vuln"
    first = vulns[0]
    assert first["analysis"]["state"] == "exploitable"
    assert first["affects"] and first["affects"][0]["ref"]
    assert first["id"]  # a GHSA/CVE advisory id
