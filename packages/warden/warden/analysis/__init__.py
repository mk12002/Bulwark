"""Warden analysis: turn an AgentSpec into signals + an agency score."""

from __future__ import annotations

from bulwark_core.signals import SignalBundle

from warden.analysis import graph, limits, prompt, scopes, secrets
from warden.analysis.score import agency_score
from warden.spec.model import AgentSpec

__all__ = ["agency_score", "collect_signals"]


def collect_signals(spec: AgentSpec) -> SignalBundle:
    """Run every analyzer over a normalized spec and return the signal bundle."""
    bundle = SignalBundle(target="agent")
    scopes.collect(spec, bundle)
    graph.collect(spec, bundle)
    limits.collect(spec, bundle)
    prompt.collect(spec, bundle)
    secrets.collect(spec, bundle)
    return bundle
