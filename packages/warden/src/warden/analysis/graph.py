"""Capability graph: source→sink reachability (A2 toxic combinations, A5 egress).

Nodes are tools and data sources; a *sensitive source* capability reachable to an
*egress sink* capability is a toxic combination. In a single-agent assembly every
tool is reachable to every other (the agent can call them in sequence), so the
"graph" is the pairing of any source-capable tool/data-source with any sink-capable
tool. This is detection-and-explanation only — never a runnable exploit.
"""

from __future__ import annotations

import re

from bulwark_core.signals import SignalBundle

from warden.spec.model import (
    HIGH_IMPACT_CAPS,
    SENSITIVE_SOURCE_CAPS,
    SINK_CAPS,
    SOURCE_CAPS,
    UNTRUSTED_INPUT_CAPS,
    AgentSpec,
    Capability,
    Gate,
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


# Sources × sinks is a cross-product, so a large assembly can emit hundreds of
# pairings. Report the first MAX_PAIRS in full and then one roll-up naming the total,
# so a big tool-set produces a readable report instead of a wall of near-duplicates.
MAX_PAIRS = 25


def collect(spec: AgentSpec, bundle: SignalBundle) -> None:
    """Emit A2 (toxic combination) and A5 (open egress) signals."""
    sources = _sources(spec)
    sinks = _sinks(spec)

    pairs = [
        (src_label, src_caps, sink_label, sink_caps)
        for src_label, src_caps in sources
        for sink_label, sink_caps in sinks
        if src_label != sink_label
    ]
    for src_label, src_caps, sink_label, sink_caps in pairs[:MAX_PAIRS]:
        bundle.add(
            "agent.toxic_combination",
            f"{src_label}->{sink_label}",
            path=f"{src_label} -> {sink_label}",
            evidence=(
                f"'{src_label}' ({src_caps}) can read sensitive data reachable to "
                f"'{sink_label}' ({sink_caps}) which sends it outward"
            ),
        )
    if len(pairs) > MAX_PAIRS:
        bundle.add(
            "agent.toxic_combination",
            f"+{len(pairs) - MAX_PAIRS} more",
            path=f"{len(sources)} source(s) -> {len(sinks)} sink(s)",
            detail=f"{len(pairs)} pairings total",
            evidence=(
                f"{len(pairs)} sensitive-source → egress-sink pairings across "
                f"{len(sources)} source(s) and {len(sinks)} sink(s); "
                f"{MAX_PAIRS} shown individually above"
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

    _collect_injectable_flows(spec, sinks, bundle)


def _collect_injectable_flows(
    spec: AgentSpec, sinks: list[tuple[str, str]], bundle: SignalBundle
) -> None:
    """Emit the *attacker-triggerable* variants of A2 — the real kill chain.

    A plain toxic combination says two capabilities *could* be chained. It becomes far
    worse when the agent also ingests untrusted external content (browse / inbound
    message): an attacker can plant instructions (indirect prompt injection) that drive
    the chain. We flag two attacker-controllable flows:

    - **inject → read secret → exfiltrate** (untrusted input + crown-jewel source + egress sink)
    - **inject → high-impact action** (untrusted input + an ungated shell/exec/financial tool)
    """
    injectors = [t for t in spec.tools if t.capabilities & UNTRUSTED_INPUT_CAPS]
    if not injectors:
        return
    inj_names = ", ".join(t.name for t in injectors[:3])

    # A gate on the sink breaks the *automated* chain: an injected instruction to
    # exfiltrate now surfaces an approval prompt to a human before anything leaves.
    # `injectable_action` already credits a declared gate; crediting it here too keeps
    # the two escalations consistent, and means the recommender's advice ("require
    # approval between reading data and any egress") measurably clears the finding.
    ungated_sinks = [
        (f"tool:{t.name}", ", ".join(sorted(c.value for c in t.capabilities & SINK_CAPS)))
        for t in spec.tools
        if (t.capabilities & SINK_CAPS) and t.gate == Gate.NONE
    ]

    crown = [t for t in spec.tools if t.capabilities & SENSITIVE_SOURCE_CAPS]
    if crown and ungated_sinks:
        src = crown[0].name
        sink = ungated_sinks[0][0]
        bundle.add(
            "agent.injectable_toxic_flow",
            f"{inj_names}=>{src}=>{sink}",
            path=f"{inj_names} -> {src} -> {sink}",
            evidence=(
                f"untrusted input ('{inj_names}') can inject instructions that drive "
                f"'{src}' (sensitive read) into '{sink}' (egress) — a fully "
                f"attacker-triggerable exfiltration path"
            ),
        )

    ungated_high = [
        t
        for t in spec.tools
        if (t.capabilities & HIGH_IMPACT_CAPS)
        and t.gate == Gate.NONE
        and not (t.capabilities & {Capability.SHELL, Capability.CODE_EXEC} and t.sandboxed)
    ]
    if ungated_high:
        target = ungated_high[0].name
        bundle.add(
            "agent.injectable_action",
            f"{inj_names}=>{target}",
            path=f"{inj_names} -> {target}",
            evidence=(
                f"untrusted input ('{inj_names}') can inject instructions that trigger "
                f"'{target}' — an ungated high-impact action — with no human in the loop"
            ),
        )


# A scope that names a concrete host, URL prefix, or CIDR is a real allow-list, even
# when it never uses the word. Matching only the literal string "allowlist" reported
# `https://api.example.com/**` as unrestricted egress — a false positive on exactly
# the configuration the finding asks the user to adopt.
_CONSTRAINED_SCOPE = re.compile(
    r"allow[-_ ]?list"
    r"|https?://[\w.-]+"  # an explicit URL prefix
    r"|\b(?:[\w-]+\.)+[a-z]{2,}\b"  # a bare hostname / domain
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b",  # an IP or CIDR
    re.IGNORECASE,
)


def _any_unrestricted_egress(net_tools: list[Tool]) -> bool:
    """True if any net_out tool lacks a constrained egress scope.

    "Constrained" means the scope names something concrete — an allow-list, a URL
    prefix, a hostname, or a CIDR. A tool with no scopes at all is unrestricted by
    omission, which is the common real-world case.
    """
    for t in net_tools:
        scopes = " ".join(t.scopes).strip()
        if not scopes or not _CONSTRAINED_SCOPE.search(scopes):
            return True
    return False
