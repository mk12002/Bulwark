"""Configuration: pydantic-settings models for AI provider, thresholds, output.

Loads from environment (prefix ``AIRLOCK_``) and an optional ``airlock.toml``.
Environment wins over the file; see :mod:`bulwark_core.config` for why. The AI layer
is off by default and never required.
"""

from __future__ import annotations

from pathlib import Path

from bulwark_core.config import AIConfig, BulwarkSettings, load_settings_for
from bulwark_core.severity import Severity
from pydantic import Field
from pydantic_settings import SettingsConfigDict

__all__ = ["AIConfig", "AirlockSettings", "load_settings"]


class AirlockSettings(BulwarkSettings):
    """Top-level runtime settings."""

    model_config = SettingsConfigDict(
        env_prefix="AIRLOCK_",
        env_nested_delimiter="__",
        extra="ignore",
        toml_file="airlock.toml",
    )

    fail_on: Severity = Severity.HIGH
    output_format: str = "terminal"
    # Fickling-style allowlist: flag pickle imports outside the ML module allowlist.
    strict_allowlist: bool = False
    ai: AIConfig = Field(default_factory=AIConfig)
    # Waivers: findings whose id or location.path match a glob are suppressed.
    suppress_rules: list[str] = Field(default_factory=list)
    suppress_paths: list[str] = Field(default_factory=list)


def load_settings(config_path: Path | None = None) -> AirlockSettings:
    """Load settings from the environment, layered over an optional ``airlock.toml``.

    Precedence: environment variables win over the TOML file (env is the trusted
    source, and API keys must come from env only).
    """
    settings: AirlockSettings = load_settings_for(AirlockSettings, config_path)
    return settings
