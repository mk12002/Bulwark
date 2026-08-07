#!/usr/bin/env python
"""Rewrite an over-privileged agent to least privilege, and prove it improved.

    python examples/04_least_privilege_recommendation.py

The recommender splits its output deliberately:

* **Applied** — mechanical hardening that preserves what the agent *does*: add a gate,
  require a sandbox, replace a wildcard scope with a visible placeholder, add limits.
* **Advisory** — anything that changes what the agent does, such as breaking a toxic
  source→sink pair. Those need a human decision and are never silently rewritten. A
  "hardened" spec that no longer performs its job is worse than none.
"""

from __future__ import annotations

from warden.recommend.least_privilege import recommend
from warden.rules import RuleEngine, load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec, Tool
from warden.spec.normalize import normalize


def main() -> int:
    spec = normalize(
        AgentSpec(
            name="support-bot",
            autonomy="autonomous",
            system_prompt="You are a support agent. Do whatever it takes to resolve the ticket.",
            tools=[
                Tool(name="read_file", description="Read a file from disk", scopes=["/**"]),
                Tool(name="run_shell", description="Run a shell command"),
                Tool(name="send_email", description="Send an email to a customer"),
                Tool(name="browse_web", description="Visit a URL and return the page"),
            ],
        )
    )

    scanner = WardenScanner(RuleEngine(load_rules()))
    before = scanner.audit_spec(spec)

    rec = recommend(spec)
    after = scanner.audit_spec(rec.hardened)

    print(f"before : score {before.score:>3}/100, {len(before.findings)} finding(s)")
    print(f"after  : score {after.score:>3}/100, {len(after.findings)} finding(s)\n")
    print(rec.diff_text())

    # The input spec is never mutated — you can audit both and compare.
    assert spec.tools[1].sandboxed is not True, "recommend() must not mutate its input"
    print("\n(the original spec is untouched — recommend() works on a deep copy)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
