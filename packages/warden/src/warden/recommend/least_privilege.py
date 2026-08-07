"""Produce a minimized (least-privilege) AgentSpec plus a human-readable diff.

Applies safe, mechanical hardening: gate high-impact tools, sandbox exec tools,
replace wildcard scopes with an explicit allow-list placeholder, add runaway guards,
and flag toxic pairs/egress that need a human design decision (never silently merged).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from warden.spec.model import (
    EXEC_CAPS,
    HIGH_IMPACT_CAPS,
    SINK_CAPS,
    SOURCE_CAPS,
    AgentSpec,
    Capability,
    Gate,
    Limits,
)
from warden.spec.normalize import has_wildcard_scope

_ALLOWLIST_PLACEHOLDER = "<allow-list: specify exact paths/hosts>"


@dataclass
class Recommendation:
    """A hardened spec plus the list of changes and advisories."""

    hardened: AgentSpec
    changes: list[str] = field(default_factory=list)  # applied, mechanical changes
    advisories: list[str] = field(default_factory=list)  # need a human decision

    def diff_text(self) -> str:
        lines = ["Least-privilege recommendation:", ""]
        if self.changes:
            lines.append("Applied:")
            lines += [f"  - {c}" for c in self.changes]
        else:
            lines.append("Applied: (nothing to harden)")
        if self.advisories:
            lines += ["", "Needs a human decision:"]
            lines += [f"  ! {a}" for a in self.advisories]
        return "\n".join(lines)


def recommend(spec: AgentSpec) -> Recommendation:
    """Return a hardened copy of ``spec`` and a description of the changes."""
    hardened = spec.model_copy(deep=True)
    rec = Recommendation(hardened=hardened)

    for tool in hardened.tools:
        if (tool.capabilities & HIGH_IMPACT_CAPS) and tool.gate == Gate.NONE:
            tool.gate = Gate.CONFIRM
            rec.changes.append(f"tool '{tool.name}': add confirm gate (high-impact action)")
        if (tool.capabilities & EXEC_CAPS) and tool.sandboxed is not True:
            tool.sandboxed = True
            rec.changes.append(f"tool '{tool.name}': require sandbox for code/shell execution")
        if has_wildcard_scope(tool):
            tool.scopes = [_ALLOWLIST_PLACEHOLDER]
            rec.changes.append(f"tool '{tool.name}': replace wildcard scope with an allow-list")

    if hardened.autonomy != "manual" and not hardened.limits.any_set():
        hardened.limits = Limits(max_iterations=25, timeout_s=300)
        rec.changes.append("agent: add runaway guards (max_iterations=25, timeout_s=300)")

    # Advisories — things Warden won't auto-rewrite because they change intent.
    has_source = any(t.capabilities & SOURCE_CAPS for t in spec.tools) or any(
        ds.sensitive for ds in spec.data_sources
    )
    has_sink = any(t.capabilities & SINK_CAPS for t in spec.tools)
    if has_source and has_sink:
        rec.advisories.append(
            "toxic combination: split the sensitive-source and egress-sink tools into "
            "separate agents, or require approval between reading data and any egress"
        )
    if any(Capability.NET_OUT in t.capabilities for t in spec.tools) and has_source:
        rec.advisories.append(
            "egress: allow-list the specific hosts the agent needs; deny all other network egress"
        )

    return rec
