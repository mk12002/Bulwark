"""Ollama provider — the default, local, free path. No key, no egress, no cost.

Talks to a local Ollama server's ``/api/chat`` endpoint. Recommended models:
``qwen2.5-coder``, ``llama3.1``, ``mistral``.
"""

from __future__ import annotations

from airlock.ai.provider import AIError


class OllamaProvider:
    """Calls a local Ollama server. Requires the ``ai`` extra (``httpx``)."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434", timeout: float = 60.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    def analyze(self, system: str, prompt: str) -> str:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise AIError("the 'ai' extra (httpx) is required for AI enrichment") from exc

        try:
            resp = httpx.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                    "options": {"temperature": 0},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # network / decode / http errors
            raise AIError(f"ollama request failed: {exc}") from exc

        message = data.get("message") if isinstance(data, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        return content if isinstance(content, str) else ""
