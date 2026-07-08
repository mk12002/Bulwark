"""Attacker-triggerable toxic flows: untrusted input turns a pairing into a kill chain."""

from __future__ import annotations

from pathlib import Path

import pytest
from bulwark_core.rules import RuleEngine
from bulwark_core.severity import Severity
from warden.rules import load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec, Capability, Tool


@pytest.fixture(scope="module")
def scanner() -> WardenScanner:
    return WardenScanner(RuleEngine(load_rules()))


def _ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.id for f in result.findings}


def test_injectable_fixture_trips_critical_flow(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "injectable.yaml"))
    ids = _ids(result)
    assert "A2-injectable-exfil-flow" in ids
    assert "A2-injectable-high-impact-action" in ids
    exfil = next(f for f in result.findings if f.id == "A2-injectable-exfil-flow")
    assert exfil.severity == Severity.CRITICAL


def test_no_untrusted_input_means_no_injectable_flow(scanner: WardenScanner) -> None:
    # Secret source + egress sink but NO untrusted input → plain A2, not the injectable variant.
    spec = AgentSpec(
        name="batch-job",
        tools=[
            Tool(name="read_secrets", capabilities={Capability.SECRET_READ}),
            Tool(name="send_webhook", capabilities={Capability.NET_OUT}),
        ],
    )
    result = scanner.audit_spec(spec)
    ids = _ids(result)
    assert "A2-toxic-combination" in ids  # the pairing still fires
    assert "A2-injectable-exfil-flow" not in ids  # but it's not attacker-triggerable


def test_untrusted_input_alone_is_not_an_exfil_flow(scanner: WardenScanner) -> None:
    # Browse only, no crown-jewel source and no egress → no injectable-exfil-flow.
    spec = AgentSpec(
        name="reader",
        tools=[Tool(name="web_browser", capabilities={Capability.BROWSE})],
    )
    result = scanner.audit_spec(spec)
    assert "A2-injectable-exfil-flow" not in _ids(result)
