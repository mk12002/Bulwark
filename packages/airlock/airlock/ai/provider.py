"""The provider abstraction and factory.

An :class:`AIProvider` is anything that can turn a (system, prompt) pair into a
text completion. Implementations live in sibling modules and are constructed by
:func:`build_provider` from an :class:`~airlock.config.AIConfig`. API keys are
read from the environment (``AIRLOCK_AI_API_KEY``) only — never from disk.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from airlock.config import AIConfig

API_KEY_ENV = "AIRLOCK_AI_API_KEY"


class AIError(Exception):
    """Raised when an AI provider is misconfigured or a call fails."""


@runtime_checkable
class AIProvider(Protocol):
    """A minimal text-completion interface. Sync, single-shot, no streaming."""

    @property
    def name(self) -> str:
        """A short identifier for the provider+model, e.g. ``ollama:llama3.1``."""
        ...

    def analyze(self, system: str, prompt: str) -> str:
        """Return the model's completion for a system + user prompt."""
        ...


def env_api_key() -> str | None:
    """Return the API key from the environment, or None if unset."""
    key = os.environ.get(API_KEY_ENV)
    return key or None


def build_provider(config: AIConfig) -> AIProvider:
    """Construct a provider from config. Raises :class:`AIError` if unavailable.

    Provider modules import ``httpx`` lazily, so this factory works even when the
    ``ai`` extra is not installed until a real call is made.
    """
    provider = config.provider.lower()
    if provider == "ollama":
        from airlock.ai.ollama import OllamaProvider

        return OllamaProvider(model=config.model, base_url=config.base_url)

    if provider == "openai_compat":
        from airlock.ai.openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(
            model=config.model,
            base_url=config.base_url,
            api_key=env_api_key(),
        )

    if provider == "anthropic":
        from airlock.ai.anthropic import AnthropicProvider

        key = env_api_key()
        if not key:
            raise AIError(
                f"provider 'anthropic' requires an API key in ${API_KEY_ENV}, but it is unset"
            )
        base = config.base_url
        # Don't send Anthropic calls to the Ollama default; use the public API base.
        if "localhost" in base or "11434" in base:
            base = "https://api.anthropic.com"
        return AnthropicProvider(model=config.model, api_key=key, base_url=base)

    raise AIError(
        f"unknown AI provider {config.provider!r}; expected ollama|openai_compat|anthropic"
    )
