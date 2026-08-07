"""Gate/sandbox/runaway analysis (A3 human-in-the-loop, A8 sandbox, A10 guards)."""

from __future__ import annotations

from bulwark_core.signals import SignalBundle

from warden.spec.model import EXEC_CAPS, HIGH_IMPACT_CAPS, AgentSpec, Gate


def collect(spec: AgentSpec, bundle: SignalBundle) -> None:
    """Emit A3, A8, and A10 signals."""
    for tool in spec.tools:
        high_impact = tool.capabilities & HIGH_IMPACT_CAPS
        if high_impact and tool.gate == Gate.NONE:
            bundle.add(
                "tool.ungated_high_impact",
                tool.name,
                path=tool.name,
                detail=", ".join(sorted(c.value for c in high_impact)),
                evidence=(
                    f"'{tool.name}' performs high-impact actions "
                    f"({', '.join(sorted(c.value for c in high_impact))}) with no human gate"
                ),
            )

        exec_caps = tool.capabilities & EXEC_CAPS
        if exec_caps and tool.sandboxed is not True:
            bundle.add(
                "tool.unsandboxed_exec",
                tool.name,
                path=tool.name,
                evidence=f"'{tool.name}' executes code/shell without a declared sandbox",
            )

    # A10 — an autonomous or looping agent with no runaway guards.
    if spec.autonomy in ("autonomous", "assisted") and not spec.limits.any_set():
        bundle.add(
            "agent.no_runaway_guards",
            spec.name,
            path=spec.name,
            evidence=(
                f"agent autonomy is '{spec.autonomy}' with no iteration cap, budget, or timeout"
            ),
        )
