"""Regression tests for capability classification and recommender consistency.

Each test pins a specific defect that was fixed: two lexicon patterns that
misclassified ordinary tools, an allow-list check that only recognised the literal
word "allowlist", and the absence of any guarantee that ``--recommend`` actually
improves the assembly by the tool's own metric.
"""

from __future__ import annotations

from warden.analysis.score import agency_score
from warden.recommend.least_privilege import recommend
from warden.rules import RuleEngine, load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec, Capability, Gate, Tool
from warden.spec.normalize import classify_tool, normalize


def _audit(spec: AgentSpec) -> list:
    normalize(spec)
    return WardenScanner(RuleEngine(load_rules())).audit_spec(spec).findings


# --------------------------------------------------------------------------- #
# Lexicon false positives
# --------------------------------------------------------------------------- #


def test_text_formatting_is_not_destructive() -> None:
    """`\\bformat\\b` used to classify a text formatter as DESTRUCTIVE (high-impact)."""
    caps = classify_tool(Tool(name="format_response", description="Format the reply as markdown"))
    assert Capability.DESTRUCTIVE not in caps


def test_disk_formatting_is_still_destructive() -> None:
    caps = classify_tool(Tool(name="format_disk", description="Format the disk before reimaging"))
    assert Capability.DESTRUCTIVE in caps


def test_mentioning_a_sandbox_is_not_code_execution() -> None:
    """"Runs in a sandbox" is a *reassurance*; it should not imply CODE_EXEC by itself."""
    caps = classify_tool(Tool(name="calc", description="Adds numbers. Runs in a sandbox."))
    assert Capability.CODE_EXEC not in caps


def test_sandboxed_code_execution_is_still_code_exec() -> None:
    caps = classify_tool(
        Tool(name="py", description="Run Python code inside a sandbox and return stdout")
    )
    assert Capability.CODE_EXEC in caps


# --------------------------------------------------------------------------- #
# A5 egress allow-listing
# --------------------------------------------------------------------------- #


def test_a_concrete_url_scope_counts_as_an_allow_list() -> None:
    """A real allow-list rarely contains the word "allowlist"; a host prefix is one."""
    spec = AgentSpec(
        name="scoped",
        tools=[
            Tool(name="get_secret", description="Read a credential from the vault"),
            Tool(
                name="post_webhook",
                description="POST JSON to a URL",
                scopes=["https://api.example.com/**"],
            ),
        ],
    )
    assert not any(f.category == "A5" for f in _audit(spec))


def test_unscoped_egress_is_still_flagged() -> None:
    spec = AgentSpec(
        name="open",
        tools=[
            Tool(name="get_secret", description="Read a credential from the vault"),
            Tool(name="post_webhook", description="POST JSON to a URL"),
        ],
    )
    assert any(f.category == "A5" for f in _audit(spec))


# --------------------------------------------------------------------------- #
# Toxic-combination pairing is capped
# --------------------------------------------------------------------------- #


def test_large_assembly_does_not_flood_the_report() -> None:
    """Sources x sinks is a cross-product; it must roll up rather than emit hundreds."""
    tools = [Tool(name=f"read_file_{i}", description="Read a file from disk") for i in range(12)]
    tools += [Tool(name=f"post_{i}", description="POST data to a URL") for i in range(12)]
    findings = _audit(AgentSpec(name="big", tools=tools))
    a2 = [f for f in findings if f.category == "A2"]
    assert 0 < len(a2) <= 30  # capped, not 144


# --------------------------------------------------------------------------- #
# The recommender must actually improve the assembly
# --------------------------------------------------------------------------- #


def test_recommendation_lowers_the_agency_score() -> None:
    """Recommender and analyzer encode the same threat model; they must agree."""
    spec = AgentSpec(
        name="over-privileged",
        autonomy="autonomous",
        tools=[
            Tool(name="run_shell", description="Run a bash command", scopes=["*"]),
            Tool(name="get_secret", description="Read a credential from the vault"),
            Tool(name="post_webhook", description="POST data to a URL"),
        ],
    )
    normalize(spec)
    before = agency_score(spec)

    rec = recommend(spec)
    normalize(rec.hardened)
    after = agency_score(rec.hardened)

    assert after < before, f"hardening did not reduce the score ({before} -> {after})"
    assert rec.changes, "expected mechanical hardening changes"
    assert rec.advisories, "a source->sink pairing needs a human decision, not a silent rewrite"


def test_recommendation_does_not_mutate_the_input_spec() -> None:
    spec = AgentSpec(
        name="x", tools=[Tool(name="run_shell", description="Run a bash command")]
    )
    normalize(spec)
    recommend(spec)
    assert spec.tools[0].gate is Gate.NONE
    assert spec.tools[0].sandboxed is not True


def test_clean_assembly_needs_no_hardening() -> None:
    spec = AgentSpec(
        name="clean",
        autonomy="manual",
        tools=[Tool(name="summarize", description="Summarize the provided text")],
    )
    normalize(spec)
    assert not recommend(spec).changes
