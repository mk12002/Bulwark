"""The agency score (0–100): a transparent, documented weighted sum.

Not a black box and never a substitute for the itemized findings — it is a headline
that summarizes how much power the assembly holds. Higher is riskier.
"""

from __future__ import annotations

from warden.spec.model import (
    EXEC_CAPS,
    HIGH_IMPACT_CAPS,
    SINK_CAPS,
    SOURCE_CAPS,
    AgentSpec,
    Capability,
    Gate,
)

# Capabilities that meaningfully widen the blast radius.
_BROAD = HIGH_IMPACT_CAPS | {Capability.NET_OUT, Capability.SECRET_READ, Capability.BROWSE}


def agency_score(spec: AgentSpec) -> int:
    """Compute the 0–100 agency score from the normalized spec.

    Weights (each term capped, total clamped to 100):
      breadth of broad capabilities        up to 40  (8 each)
      ungated high-impact tools            up to 25  (10 each)
      a source→sink toxic combination      20
      unsandboxed code/shell execution     10
      missing runaway guards (autonomous)   8
      unrestricted egress with a source     5
    """
    score = 0

    broad = spec.all_capabilities() & _BROAD
    score += min(len(broad) * 8, 40)

    ungated = sum(
        1 for t in spec.tools if (t.capabilities & HIGH_IMPACT_CAPS) and t.gate == Gate.NONE
    )
    score += min(ungated * 10, 25)

    has_source = any(t.capabilities & SOURCE_CAPS for t in spec.tools) or any(
        ds.sensitive for ds in spec.data_sources
    )
    has_sink = any(t.capabilities & SINK_CAPS for t in spec.tools)
    if has_source and has_sink:
        score += 20

    if any((t.capabilities & EXEC_CAPS) and t.sandboxed is not True for t in spec.tools):
        score += 10

    if spec.autonomy != "manual" and not spec.limits.any_set():
        score += 8

    if any(Capability.NET_OUT in t.capabilities for t in spec.tools) and has_source:
        score += 5

    return max(0, min(score, 100))
