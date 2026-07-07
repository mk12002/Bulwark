"""Warden runtime settings (env prefix ``WARDEN_``)."""

from __future__ import annotations

from bulwark_core.config import AIConfig
from bulwark_core.severity import Severity
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["AIConfig", "WardenSettings", "load_settings"]


class WardenSettings(BaseSettings):
    """Top-level Warden settings."""

    model_config = SettingsConfigDict(
        env_prefix="WARDEN_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    fail_on: Severity = Severity.HIGH
    output_format: str = "terminal"
    ai: AIConfig = Field(default_factory=AIConfig)


def load_settings() -> WardenSettings:
    """Load Warden settings from the environment."""
    return WardenSettings()
