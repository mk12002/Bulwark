"""Scope breadth analysis (A1 excessive tool scope, A7 excessive data access)."""

from __future__ import annotations

from bulwark_core.signals import SignalBundle

from warden.spec.model import AgentSpec, Capability
from warden.spec.normalize import has_wildcard_scope

_BROAD_CAPS = {Capability.SHELL, Capability.FS_WRITE, Capability.FS_READ, Capability.NET_OUT}


def collect(spec: AgentSpec, bundle: SignalBundle) -> None:
    """Emit A1 (excessive tool scope) and A7 (excessive data access) signals."""
    for tool in spec.tools:
        broad = tool.capabilities & _BROAD_CAPS
        if has_wildcard_scope(tool):
            bundle.add(
                "tool.excessive_scope",
                tool.name,
                path=tool.name,
                detail=", ".join(tool.scopes),
                evidence=f"'{tool.name}' declares a wildcard/unconstrained scope",
            )
        elif broad and not tool.scopes:
            bundle.add(
                "tool.excessive_scope",
                tool.name,
                path=tool.name,
                evidence=(
                    f"'{tool.name}' has broad capability "
                    f"({', '.join(sorted(c.value for c in broad))}) with no scope constraint"
                ),
            )

    sensitive = [ds for ds in spec.data_sources if ds.sensitive]
    rooty = [ds for ds in spec.data_sources if ds.scope in ("/", "*", "**", "~", "root")]
    if len(sensitive) >= 2 or rooty:
        names = ", ".join(ds.name for ds in (rooty or sensitive)[:5])
        bundle.add(
            "agent.excessive_data",
            names,
            path=names,
            evidence=f"agent reads broad/sensitive data sources: {names}",
        )
