"""Optional, provider-agnostic AI enrichment layer.

This is a bonus layer, **off by default**. Airlock is fully useful with zero AI
configured — every core finding comes from deterministic static analysis. AI only
*enriches* (semantic judgement, triage, summaries), never replaces deterministic
findings, and any AI output is tagged ``source="ai"`` and clearly separated.

See ``docs/PROJECT_REFERENCE.md`` §9 for the design.
"""

from __future__ import annotations

from airlock.ai.enrich import EnrichmentOutcome, run_enrichment
from airlock.ai.provider import AIError, AIProvider, build_provider

__all__ = [
    "AIError",
    "AIProvider",
    "EnrichmentOutcome",
    "build_provider",
    "run_enrichment",
]
