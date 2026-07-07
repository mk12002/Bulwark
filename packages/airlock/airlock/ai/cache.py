"""A persistent, content-addressed cache wrapper for AI providers.

Identical (system, prompt) pairs — e.g. the same tool description across many
scans — are answered from disk instead of re-calling the model, capping cost and
latency. The cache is keyed by a hash of provider+system+prompt and stored as JSON
in the Airlock state dir.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from airlock.ai.provider import AIProvider


def state_dir() -> Path:
    """Return the Airlock state dir (``AIRLOCK_STATE_DIR`` or ``~/.airlock``)."""
    base = os.environ.get("AIRLOCK_STATE_DIR")
    return Path(base) if base else Path.home() / ".airlock"


class CachingProvider:
    """Wraps an :class:`AIProvider`, memoizing completions to disk.

    Exposes ``calls`` (delegated model calls) and ``hits`` (cache hits) for
    cost accounting.
    """

    def __init__(self, inner: AIProvider, cache_path: Path | None = None):
        self._inner = inner
        self._path = cache_path or (state_dir() / "ai_cache.json")
        self._cache = self._load()
        self.calls = 0
        self.hits = 0

    @property
    def name(self) -> str:
        return self._inner.name

    def _load(self) -> dict[str, str]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _persist(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._cache), encoding="utf-8")
        except OSError:
            pass

    def _key(self, system: str, prompt: str) -> str:
        basis = f"{self._inner.name}\x00{system}\x00{prompt}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def analyze(self, system: str, prompt: str) -> str:
        key = self._key(system, prompt)
        if key in self._cache:
            self.hits += 1
            return self._cache[key]
        result = self._inner.analyze(system, prompt)
        self.calls += 1
        self._cache[key] = result
        self._persist()
        return result
