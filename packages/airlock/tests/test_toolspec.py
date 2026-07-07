"""Tests for the toolspec scanner (OpenAI/Anthropic/LangChain tool definitions)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from airlock.rules import RuleEngine, load_rules
from airlock.scanners.mcp import MCPScanner
from airlock.scanners.toolspec import ToolSpecError, load_toolspec

REPO_ROOT = Path(__file__).resolve().parents[1]
FIX = REPO_ROOT / "fixtures" / "toolspec"


def _scan(path: Path):
    inv = load_toolspec(path)
    return MCPScanner(RuleEngine(load_rules()), connector=lambda _t: inv).scan(str(path))


def test_poisoned_openai_spec_reports_p1_and_p4() -> None:
    cats = {f.category for f in _scan(FIX / "poisoned_openai.json").findings}
    assert "P1" in cats
    assert "P4" in cats


def test_clean_anthropic_spec_is_clean() -> None:
    assert _scan(FIX / "clean_anthropic.json").findings == []


def test_loader_parses_openai_dialect() -> None:
    inv = load_toolspec(FIX / "poisoned_openai.json")
    names = {t.name for t in inv.tools}
    assert names == {"run_shell", "upload_to_url"}
    assert all(isinstance(t.input_schema, dict) for t in inv.tools)


def test_loader_parses_langchain_plain_list(tmp_path: Path) -> None:
    p = tmp_path / "tools.json"
    p.write_text(
        json.dumps(
            [
                {
                    "name": "search",
                    "description": "Search the web.",
                    "args_schema": {"type": "object"},
                },
                {"name": "calc", "description": "Do math."},
            ]
        )
    )
    inv = load_toolspec(p)
    assert {t.name for t in inv.tools} == {"search", "calc"}


def test_loader_parses_yaml(tmp_path: Path) -> None:
    p = tmp_path / "tools.yaml"
    p.write_text("tools:\n  - name: run\n    description: Execute a shell command.\n")
    inv = load_toolspec(p)
    assert inv.tools[0].name == "run"


def test_secret_in_openai_parameter_default_trips_p6(tmp_path: Path) -> None:
    p = tmp_path / "tools.json"
    p.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "deploy",
                            "description": "Deploy the app.",
                            "parameters": {
                                "properties": {
                                    "token": {
                                        "type": "string",
                                        "default": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                                    }
                                }
                            },
                        },
                    }
                ]
            }
        )
    )
    assert "P6" in {f.category for f in _scan(p).findings}


def test_loader_parses_bedrock_dialect(tmp_path: Path) -> None:
    p = tmp_path / "tools.json"
    p.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "toolSpec": {
                            "name": "lookup",
                            "description": "Look something up.",
                            "inputSchema": {"json": {"type": "object", "properties": {}}},
                        }
                    }
                ]
            }
        )
    )
    inv = load_toolspec(p)
    assert inv.tools[0].name == "lookup"
    assert isinstance(inv.tools[0].input_schema, dict)


def test_loader_single_top_level_tool(tmp_path: Path) -> None:
    p = tmp_path / "tool.json"
    p.write_text(json.dumps({"name": "solo", "description": "One tool."}))
    inv = load_toolspec(p)
    assert [t.name for t in inv.tools] == ["solo"]


def test_loader_skips_nameless_items(tmp_path: Path) -> None:
    p = tmp_path / "tools.json"
    p.write_text(json.dumps([{"description": "no name"}, {"name": "ok", "description": "d"}]))
    inv = load_toolspec(p)
    assert [t.name for t in inv.tools] == ["ok"]


def test_loader_empty_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "empty.json"
    p.write_text("")
    with pytest.raises(ToolSpecError):
        load_toolspec(p)


def test_loader_bad_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("tools: [unclosed\n")
    with pytest.raises(ToolSpecError):
        load_toolspec(p)


def test_cli_scan_toolspec_gates() -> None:
    from airlock.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", "toolspec", str(FIX / "poisoned_openai.json"), "--format", "json"]
    )
    assert result.exit_code == 1  # P1/P4 at/above the default high threshold
    assert '"P4"' in result.stdout
