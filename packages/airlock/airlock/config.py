"""Configuration: pydantic-settings models for AI provider, thresholds, output.

Loads from environment (prefix ``AIRLOCK_``) and an optional ``airlock.toml``.
The AI layer is off by default and never required.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from airlock.core.severity import Severity


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


class AirlockSettings(BaseSettings):
    """Top-level runtime settings."""

    model_config = SettingsConfigDict(
        env_prefix="AIRLOCK_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    fail_on: Severity = Severity.HIGH
    output_format: str = "terminal"
    ai: AIConfig = Field(default_factory=AIConfig)
    # Waivers: findings whose id or location.path match a glob are suppressed.
    suppress_rules: list[str] = Field(default_factory=list)
    suppress_paths: list[str] = Field(default_factory=list)


def load_settings(config_path: Path | None = None) -> AirlockSettings:
    """Load settings, overlaying an optional ``airlock.toml`` under env values.

    Precedence: environment variables win over the TOML file (env is the trusted
    source, and API keys must come from env only).
    """
    file_values: dict = {}
    path = config_path or Path("airlock.toml")
    if path.exists():
        with path.open("rb") as fh:
            file_values = tomllib.load(fh)
    # Env-sourced settings first, then fill gaps from the TOML file.
    settings = AirlockSettings()
    if file_values:
        merged = settings.model_dump()
        _deep_fill(merged, file_values)
        settings = AirlockSettings.model_validate(merged)
    return settings


def _deep_fill(base: dict, overlay: dict) -> None:
    """Fill only keys of ``base`` that hold default-ish values from ``overlay``."""
    for key, val in overlay.items():
        if key not in base:
            continue
        if isinstance(val, dict) and isinstance(base.get(key), dict):
            _deep_fill(base[key], val)
