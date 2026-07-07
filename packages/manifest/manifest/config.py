"""Manifest runtime settings (env prefix ``MANIFEST_``)."""

from __future__ import annotations

from bulwark_core.config import AIConfig
from bulwark_core.severity import Severity
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["AIConfig", "ManifestSettings", "load_settings"]


class ManifestSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MANIFEST_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    fail_on: Severity = Severity.HIGH
    output_format: str = "terminal"
    ai: AIConfig = Field(default_factory=AIConfig)


def load_settings() -> ManifestSettings:
    return ManifestSettings()
