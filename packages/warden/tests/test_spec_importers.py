"""Tests for the AgentSpec IR, normalize lexicon, and importers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from warden.importers import ImportError_, import_agent
from warden.importers.manifest_yaml import parse_file
from warden.spec.model import AgentSpec, Capability, Gate, Tool
from warden.spec.normalize import classify_tool, has_wildcard_scope, normalize


def test_classify_tool_shell_and_exec() -> None:
    caps = classify_tool(Tool(name="run_shell", description="Execute a shell command."))
    assert Capability.SHELL in caps


def test_classify_tool_network() -> None:
    caps = classify_tool(
        Tool(name="post", description="Send data to any external URL via HTTP POST.")
    )
    assert Capability.NET_OUT in caps


def test_classify_tool_unknown() -> None:
    caps = classify_tool(Tool(name="add", description="Add two numbers."))
    assert caps == {Capability.UNKNOWN}


def test_wildcard_scope_detection() -> None:
    assert has_wildcard_scope(Tool(name="x", scopes=["*"]))
    assert has_wildcard_scope(Tool(name="x", scopes=["/etc/**"]))
    assert not has_wildcard_scope(Tool(name="x", scopes=["/home/app/data"]))


def test_normalize_marks_sensitive_data() -> None:
    spec = AgentSpec(
        name="a",
        tools=[Tool(name="read", description="read files")],
        data_sources=[
            __import__("warden.spec.model", fromlist=["DataSource"]).DataSource(
                name="env", kind="secret"
            )
        ],
    )
    normalize(spec)
    assert spec.data_sources[0].sensitive is True
    assert spec.tools[0].capabilities  # tagged


def test_import_manifest_yaml(fixtures: Path) -> None:
    spec, importer = import_agent(fixtures / "over_privileged" / "exfil.yaml")
    assert importer == "manifest"
    assert spec.name == "research-assistant"
    assert spec.autonomy == "autonomous"
    assert {t.name for t in spec.tools} == {"read_notes", "post_webhook"}
    # normalize ran → capabilities tagged
    assert any(t.capabilities for t in spec.tools)


def test_import_mcp_config(fixtures: Path) -> None:
    spec, importer = import_agent(fixtures / "over_privileged" / "mcp_client.json")
    assert importer == "mcp_config"
    assert len(spec.mcp_servers) == 2
    assert any("filesystem" in s for s in spec.mcp_servers)


def test_manifest_round_trips_gate_and_scopes(tmp_path: Path) -> None:
    p = tmp_path / "agent.yaml"
    p.write_text(
        "name: t\ntools:\n  - name: pay\n    description: charge a card\n    gate: approval\n",
        encoding="utf-8",
    )
    spec = parse_file(p)
    assert spec.tools[0].gate == Gate.APPROVAL


def test_import_unknown_config_raises(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"unrelated": 1}), encoding="utf-8")
    with pytest.raises(ImportError_):
        import_agent(p)
