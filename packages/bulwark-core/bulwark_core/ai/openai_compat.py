"""OpenAI-compatible provider (BYO key/base_url).

One implementation covers OpenAI, OpenRouter, LM Studio, and self-hosted vLLM —
all expose ``/v1/chat/completions``. Configure ``base_url`` + ``model`` and set
the key in ``AIRLOCK_AI_API_KEY``.
"""

from __future__ import annotations

from bulwark_core.ai.provider import AIError


class OpenAICompatProvider:
    """Calls an OpenAI-compatible ``/v1/chat/completions`` endpoint."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 60.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    @property
    def name(self) -> str:
        return f"openai_compat:{self.model}"

    def analyze(self, system: str, prompt: str) -> str:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise AIError("the 'ai' extra (httpx) is required for AI enrichment") from exc

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = httpx.post(
                f"{self.base_url}/v1/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise AIError(f"openai-compatible request failed: {exc}") from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIError(f"unexpected openai-compatible response shape: {exc}") from exc
        return content if isinstance(content, str) else ""
