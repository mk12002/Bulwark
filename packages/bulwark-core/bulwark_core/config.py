"""Shared configuration models and the TOML/env layering used by every tool.

``AIConfig`` is the provider-agnostic AI enrichment config reused by every tool
(Airlock, Warden, Manifest). ``BulwarkSettings`` is the base every tool's settings
class extends so that all three layer configuration identically.

**Precedence** (highest first): explicit init kwargs, environment variables, the
tool's TOML file, then any secrets directory. Environment beats file deliberately:
env is the operator's channel (CI, containers), while a committed config file may be
controlled by the very repository being scanned, so a file must never be able to
weaken a pipeline's settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

__all__ = ["AIConfig", "BulwarkSettings", "load_settings_for"]


class AIConfig(BaseModel):
    """Optional AI enrichment settings. Disabled by default.

    The API key is intentionally NOT a field here: it is read from the environment
    variable ``AIRLOCK_AI_API_KEY`` at provider-build time and never from disk. A
    config file lives in a repository, gets committed, and ends up in issue reports;
    making the field structurally absent means there is nowhere to put a key.
    """

    enabled: bool = False
    provider: str = "ollama"  # ollama | openai_compat | anthropic
    model: str = "qwen2.5-coder"
    base_url: str = "http://localhost:11434"
    max_findings_to_enrich: int = 25


class BulwarkSettings(BaseSettings):
    """Base settings class: env overrides TOML, TOML overrides defaults.

    Subclasses set ``env_prefix`` and ``toml_file`` in their own ``model_config``.
    Use :func:`load_settings_for` to load with an explicit config path.
    """

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order the sources highest-precedence first."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


def load_settings_for(
    settings_cls: type[BulwarkSettings], config_path: Path | None = None
) -> Any:
    """Instantiate ``settings_cls``, optionally reading a specific TOML file.

    With no ``config_path`` the class's declared ``toml_file`` is used (missing files
    are ignored by pydantic-settings). With one, a scoped subclass is created so the
    override applies to this call only.
    """
    if config_path is None:
        return settings_cls()

    scoped = type(
        f"{settings_cls.__name__}Scoped",
        (settings_cls,),
        {
            "model_config": SettingsConfigDict(
                **{**settings_cls.model_config, "toml_file": str(config_path)}
            )
        },
    )
    return scoped()
