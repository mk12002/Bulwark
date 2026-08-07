#!/usr/bin/env python
"""Audit an agent assembly for excessive agency — built in memory, no file needed.

    python examples/02_audit_an_agent.py

Airlock asks "is this part safe?". Warden asks a question no part-level scanner can:
*given how these parts are wired together, does the agent hold more power than its job
needs?* Every tool below is individually reasonable. The combination is not.

``audit_spec`` takes an in-memory ``AgentSpec``, so you can score a hypothetical design
before writing any config — useful in tests and in design review.
"""

from __future__ import annotations

from warden.rules import RuleEngine, load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec, Gate, Tool


def audit(label: str, spec: AgentSpec) -> None:
    result = WardenScanner(RuleEngine(load_rules())).audit_spec(spec)
    cats = sorted({f"{f.category}/{f.severity.value}" for f in result.findings})
    print(f"{label:38} score={result.score:>3}/100  {cats}")


def main() -> int:
    # One capability at a time — watch the severity escalate as the assembly
    # accumulates the three legs of the "lethal trifecta".
    secret = Tool(name="get_secret", description="Read a credential from the vault")
    egress = Tool(name="post_webhook", description="POST data to a URL")
    browse = Tool(name="browse_web", description="Visit a URL and return the page")

    audit("secrets only", AgentSpec(name="a", tools=[secret]))
    audit("secrets + egress", AgentSpec(name="b", tools=[secret, egress]))

    # Adding a *browsing* tool reads nothing sensitive and sends nothing outward —
    # yet it escalates the assembly to CRITICAL, because it completes the trifecta:
    # an attacker can now plant instructions the agent will read and act on.
    audit("secrets + egress + browsing", AgentSpec(name="c", tools=[secret, egress, browse]))

    # Gating the obvious sink is NOT enough, and this is the interesting part.
    # `browse_web` fetches URLs, so it carries net_out too — a second, ungated egress
    # path. A human reviewing this design sees "I gated the webhook" and moves on.
    gated_hook = Tool(name="post_webhook", description="POST data to a URL", gate=Gate.APPROVAL)
    audit("...gate the webhook only", AgentSpec(name="d", tools=[secret, gated_hook, browse]))

    # Gate every egress-capable tool and the attacker-triggerable chain is broken.
    gated_browse = Tool(
        name="browse_web", description="Visit a URL and return the page", gate=Gate.APPROVAL
    )
    audit("...gate every egress path", AgentSpec(name="e", tools=[secret, gated_hook, gated_browse]))

    print(
        "\nTwo lessons. The finding is about the *combination* — no single tool is\n"
        "wrong, which is why part-level scanning misses it. And 'I gated the obvious\n"
        "one' is the mistake the capability model catches: browse_web fetches URLs, so\n"
        "it is an egress path too, whatever its name suggests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
