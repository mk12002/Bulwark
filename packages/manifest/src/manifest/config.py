"""Manifest runtime settings (env prefix ``MANIFEST_``, optional ``manifest.toml``)."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.config import AIConfig, BulwarkSettings, load_settings_for
from bulwark_core.severity import Severity
from pydantic import Field
from pydantic_settings import SettingsConfigDict

__all__ = ["AIConfig", "ManifestSettings", "load_settings"]


class ManifestSettings(BulwarkSettings):
    """Top-level Manifest settings."""

    model_config = SettingsConfigDict(
        env_prefix="MANIFEST_",
        env_nested_delimiter="__",
        extra="ignore",
        toml_file="manifest.toml",
    )

    fail_on: Severity = Severity.HIGH
    output_format: str = "terminal"
    ai: AIConfig = Field(default_factory=AIConfig)


def load_settings(config_path: Path | None = None) -> ManifestSettings:
    """Load Manifest settings from the environment, over an optional ``manifest.toml``."""
    settings: ManifestSettings = load_settings_for(ManifestSettings, config_path)
    return settings
