"""Regression tests for two capability-model bugs found while writing examples/.

Both were silent: the analysis ran, produced findings, and simply missed the most
severe one — the failure mode that matters most for a security tool, because the user
sees a clean-looking result rather than an error.
"""

from __future__ import annotations

from bulwark_core.severity import Severity

from warden.rules import RuleEngine, load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec, Capability, Gate, Tool
from warden.spec.normalize import classify_tool


def _caps(name: str, description: str = "") -> set[Capability]:
    return classify_tool(Tool(name=name, description=description))


def _audit(spec: AgentSpec):
    return WardenScanner(RuleEngine(load_rules())).audit_spec(spec)


# --------------------------------------------------------------------------- #
# Bug 1: `_` is a regex word character, so \bbrowse\b never matched browse_web.
# snake_case is the dominant tool-naming convention, so several capabilities were
# unclassifiable under real-world names.
# --------------------------------------------------------------------------- #


def test_snake_case_tool_names_are_classified() -> None:
    assert Capability.BROWSE in _caps("browse_web", "Visit a URL and return the page")
    assert Capability.SHELL in _caps("run_shell", "Run a command")
    assert Capability.FS_READ in _caps("read_file", "Read a file")
    assert Capability.FS_WRITE in _caps("write_file", "Write a file")
    assert Capability.SECRET_READ in _caps("get_secret", "Read a credential")
    assert Capability.EMAIL_SEND in _caps("send_email", "Send an email")


def test_hyphenated_tool_names_are_classified() -> None:
    assert Capability.BROWSE in _caps("browse-web", "Fetch a page")


def test_desnaking_does_not_break_literal_patterns() -> None:
    """Patterns matching the raw underscored form must keep working."""
    assert Capability.SHELL in _caps("exec_cmd", "")
    assert Capability.CODE_EXEC in _caps("run_python", "Execute python code in a sandbox")


def test_desnaking_does_not_resurrect_known_false_positives() -> None:
    """The narrowed patterns must stay narrow once underscores become spaces."""
    assert _caps("format_response", "Format the reply as markdown") == {Capability.UNKNOWN}
    assert _caps("open_ticket", "Open a support ticket in the tracker") != {Capability.FS_READ}


# --------------------------------------------------------------------------- #
# Bug 2: the CRITICAL injectable-exfiltration flow ignored gates on the sink, while
# the sibling injectable-action check credited them. A declared approval gate breaks
# the automated chain, so the two escalations must agree.
# --------------------------------------------------------------------------- #


def _trifecta(sink_gate: Gate, browse_gate: Gate = Gate.NONE) -> AgentSpec:
    return AgentSpec(
        name="t",
        tools=[
            Tool(name="get_secret", description="Read a credential from the vault"),
            Tool(name="post_webhook", description="POST data to a URL", gate=sink_gate),
            Tool(
                name="browse_web",
                description="Visit a URL and return the page",
                gate=browse_gate,
            ),
        ],
    )


def _has_critical_a2(spec: AgentSpec) -> bool:
    return any(
        f.category == "A2" and f.severity is Severity.CRITICAL for f in _audit(spec).findings
    )


def test_trifecta_is_critical_when_every_sink_is_ungated() -> None:
    assert _has_critical_a2(_trifecta(Gate.NONE))


def test_gating_one_sink_is_not_enough_when_another_carries_egress() -> None:
    """browse_web fetches URLs, so it is an egress path too — the finding must persist."""
    assert _has_critical_a2(_trifecta(Gate.APPROVAL))


def test_gating_every_egress_path_clears_the_critical_flow() -> None:
    assert not _has_critical_a2(_trifecta(Gate.APPROVAL, browse_gate=Gate.APPROVAL))
