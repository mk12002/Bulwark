"""Warden runtime settings (env prefix ``WARDEN_``, optional ``warden.toml``)."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.config import AIConfig, BulwarkSettings, load_settings_for
from bulwark_core.severity import Severity
from pydantic import Field
from pydantic_settings import SettingsConfigDict

__all__ = ["AIConfig", "WardenSettings", "load_settings"]


class WardenSettings(BulwarkSettings):
    """Top-level Warden settings."""

    model_config = SettingsConfigDict(
        env_prefix="WARDEN_",
        env_nested_delimiter="__",
        extra="ignore",
        toml_file="warden.toml",
    )

    fail_on: Severity = Severity.HIGH
    output_format: str = "terminal"
    profile: str = "balanced"
    ai: AIConfig = Field(default_factory=AIConfig)


def load_settings(config_path: Path | None = None) -> WardenSettings:
    """Load Warden settings from the environment, over an optional ``warden.toml``."""
    settings: WardenSettings = load_settings_for(WardenSettings, config_path)
    return settings
