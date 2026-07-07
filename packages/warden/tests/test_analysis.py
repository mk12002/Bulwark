"""Tests for the analysis engine: signals per A-code and the agency score."""

from __future__ import annotations

from warden.analysis import agency_score, collect_signals
from warden.spec.model import AgentSpec, DataSource, Gate, Limits, Tool
from warden.spec.normalize import normalize


def _spec(**kw) -> AgentSpec:
    spec = AgentSpec(**kw)
    return normalize(spec)


def _signals(spec: AgentSpec) -> set[str]:
    return {s.name for s in collect_signals(spec).signals}


def test_a2_toxic_combination_and_a5() -> None:
    spec = _spec(
        name="a",
        autonomy="autonomous",
        tools=[
            Tool(name="read_notes", description="Read private secrets from files.", scopes=["~/n"]),
            Tool(name="post", description="Send data to any external URL via HTTP POST."),
        ],
        data_sources=[DataSource(name="n", kind="files", scope="~/n", sensitive=True)],
    )
    names = _signals(spec)
    assert "agent.toxic_combination" in names
    assert "agent.open_egress" in names


def test_a3_ungated_high_impact() -> None:
    spec = _spec(name="a", tools=[Tool(name="rm", description="delete files", gate=Gate.NONE)])
    assert "tool.ungated_high_impact" in _signals(spec)


def test_a3_gated_tool_is_ok() -> None:
    spec = _spec(name="a", tools=[Tool(name="rm", description="delete files", gate=Gate.CONFIRM)])
    assert "tool.ungated_high_impact" not in _signals(spec)


def test_a8_unsandboxed_exec_and_sandboxed_ok() -> None:
    unsandboxed = _spec(name="a", tools=[Tool(name="sh", description="run shell command")])
    assert "tool.unsandboxed_exec" in _signals(unsandboxed)
    sandboxed = _spec(
        name="a", tools=[Tool(name="sh", description="run shell command", sandboxed=True)]
    )
    assert "tool.unsandboxed_exec" not in _signals(sandboxed)


def test_a10_runaway_guards() -> None:
    no_limits = _spec(name="a", autonomy="autonomous")
    assert "agent.no_runaway_guards" in _signals(no_limits)
    with_limits = _spec(name="a", autonomy="autonomous", limits=Limits(max_iterations=10))
    assert "agent.no_runaway_guards" not in _signals(with_limits)


def test_a4_weak_prompt() -> None:
    spec = _spec(name="a", system_prompt="Do whatever it takes to finish.")
    assert "agent.weak_prompt" in _signals(spec)


def test_a1_wildcard_scope() -> None:
    spec = _spec(name="a", tools=[Tool(name="fs", description="read files", scopes=["*"])])
    assert "tool.excessive_scope" in _signals(spec)


def test_a6_embedded_secret() -> None:
    spec = _spec(
        name="a",
        tools=[Tool(name="t", description="api_key = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")],
    )
    assert "agent.embedded_secret" in _signals(spec)


def test_a9_unscanned_parts() -> None:
    spec = _spec(name="a", mcp_servers=["files: npx server /"])
    assert "agent.unscanned_parts" in _signals(spec)


def test_agency_score_orders_by_power() -> None:
    dangerous = _spec(
        name="a",
        autonomy="autonomous",
        tools=[
            Tool(name="sh", description="run shell command"),
            Tool(name="read", description="read secrets from files", scopes=["*"]),
            Tool(name="post", description="http post to any url"),
        ],
    )
    calm = _spec(
        name="b",
        autonomy="assisted",
        tools=[Tool(name="add", description="add numbers")],
        limits=Limits(max_iterations=5),
    )
    assert agency_score(dangerous) > agency_score(calm)
    assert 0 <= agency_score(calm) <= 100
    assert agency_score(calm) == 0
