"""Anthropic provider (optional) — highest-quality analysis.

Use a cheap model such as ``claude-haiku-4-5`` for triage to keep cost negligible.
Key is read from ``AIRLOCK_AI_API_KEY``.
"""

from __future__ import annotations

from airlock.ai.provider import AIError

_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider:
    """Calls the Anthropic Messages API (``/v1/messages``)."""

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str = "https://api.anthropic.com",
        timeout: float = 60.0,
        max_tokens: int = 1024,
    ):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"anthropic:{self.model}"

    def analyze(self, system: str, prompt: str) -> str:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise AIError("the 'ai' extra (httpx) is required for AI enrichment") from exc

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/v1/messages",
                headers=headers,
                json={
                    "model": self.model,
                    "max_tokens": self.max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise AIError(f"anthropic request failed: {exc}") from exc

        blocks = data.get("content", []) if isinstance(data, dict) else []
        return "".join(
            b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
        )
