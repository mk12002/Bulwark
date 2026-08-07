"""System-prompt authority + injectability heuristics (A4).

Deterministic keyword heuristics here; the AI layer (Phase 4) can add semantic
judgement. Absence of a prompt is itself weak-guardrail signal for an agent with
high-impact tools.
"""

from __future__ import annotations

import re

from bulwark_core.signals import SignalBundle

from warden.spec.model import HIGH_IMPACT_CAPS, AgentSpec

_OVERBROAD = re.compile(
    r"(?i)(do whatever it takes|by any means|you may (access|do|use) anything|"
    r"unlimited|no restrictions|without asking|never refuse|ignore (safety|limits)|"
    r"full (access|control|autonomy)|act autonomously)"
)


def collect(spec: AgentSpec, bundle: SignalBundle) -> None:
    """Emit A4 signals for over-broad or missing system-prompt guardrails."""
    prompt = spec.system_prompt or ""
    if _OVERBROAD.search(prompt):
        match = _OVERBROAD.search(prompt)
        bundle.add(
            "agent.weak_prompt",
            spec.name,
            path=spec.name,
            evidence=f"system prompt grants open-ended authority: '{match.group(0)}'"
            if match
            else "system prompt grants open-ended authority",
        )
    elif not prompt.strip() and (spec.all_capabilities() & HIGH_IMPACT_CAPS):
        bundle.add(
            "agent.weak_prompt",
            spec.name,
            path=spec.name,
            evidence="agent has high-impact tools but no system prompt / guardrails",
        )
