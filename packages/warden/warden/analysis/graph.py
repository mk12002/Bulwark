"""Capability graph: source→sink reachability (A2 toxic combinations, A5 egress).

Nodes are tools and data sources; a *sensitive source* capability reachable to an
*egress sink* capability is a toxic combination. In a single-agent assembly every
tool is reachable to every other (the agent can call them in sequence), so the
"graph" is the pairing of any source-capable tool/data-source with any sink-capable
tool. This is detection-and-explanation only — never a runnable exploit.
"""

from __future__ import annotations

from bulwark_core.signals import SignalBundle

from warden.spec.model import (
    SINK_CAPS,
    SOURCE_CAPS,
    AgentSpec,
    Capability,
    Tool,
)


def _sources(spec: AgentSpec) -> list[tuple[str, str]]:
    """Return (label, detail) for every sensitive-source in the assembly."""
    out: list[tuple[str, str]] = []
    for t in spec.tools:
        caps = t.capabilities & SOURCE_CAPS
        if caps:
            out.append((f"tool:{t.name}", ", ".join(sorted(c.value for c in caps))))
    for ds in spec.data_sources:
        if ds.sensitive:
            out.append((f"data:{ds.name}", ds.kind))
    return out


def _sinks(spec: AgentSpec) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for t in spec.tools:
        caps = t.capabilities & SINK_CAPS
        if caps:
            out.append((f"tool:{t.name}", ", ".join(sorted(c.value for c in caps))))
    return out


def collect(spec: AgentSpec, bundle: SignalBundle) -> None:
    """Emit A2 (toxic combination) and A5 (open egress) signals."""
    sources = _sources(spec)
    sinks = _sinks(spec)

    for src_label, src_caps in sources:
        for sink_label, sink_caps in sinks:
            if src_label == sink_label:
                continue
            bundle.add(
                "agent.toxic_combination",
                f"{src_label}->{sink_label}",
                path=f"{src_label} -> {sink_label}",
                evidence=(
                    f"'{src_label}' ({src_caps}) can read sensitive data reachable to "
                    f"'{sink_label}' ({sink_caps}) which sends it outward"
                ),
            )

    # A5 — an unrestricted network egress in the presence of any sensitive source.
    net_tools = [t for t in spec.tools if Capability.NET_OUT in t.capabilities]
    if net_tools and sources and _any_unrestricted_egress(net_tools):
        names = ", ".join(t.name for t in net_tools[:5])
        bundle.add(
            "agent.open_egress",
            names,
            path=names,
            evidence=(
                f"network egress ({names}) is not allow-listed while sensitive sources exist"
            ),
        )


def _any_unrestricted_egress(net_tools: list[Tool]) -> bool:
    """True if any net_out tool lacks an allow-list scope (heuristic)."""
    for t in net_tools:
        scopes = " ".join(t.scopes).lower()
        if not scopes or ("allowlist" not in scopes and "allow-list" not in scopes):
            return True
    return False
