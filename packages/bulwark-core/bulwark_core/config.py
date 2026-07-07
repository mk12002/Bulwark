"""Shared configuration models for the Bulwark suite.

``AIConfig`` is the provider-agnostic AI enrichment config reused by every tool
(Airlock, Warden, Manifest). Tool-level settings (env prefix, thresholds, waivers)
live in each tool's own ``config`` module.
"""

from __future__ import annotations

from pydantic import BaseModel


class AIConfig(BaseModel):
    """Optional AI enrichment settings. Disabled by default.

    The API key is intentionally NOT a field here: it is read from the environment
    variable ``AIRLOCK_AI_API_KEY`` at provider-build time and never from disk.
    """

    enabled: bool = False
    provider: str = "ollama"  # ollama | openai_compat | anthropic
    model: str = "qwen2.5-coder"
    base_url: str = "http://localhost:11434"
    max_findings_to_enrich: int = 25
