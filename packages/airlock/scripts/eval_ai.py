"""Run the AI semantic-detector evaluation against the configured provider.

Usage:  AIRLOCK_AI__ENABLED=true python scripts/eval_ai.py
Requires a reachable provider (e.g. a local Ollama server).
"""

from __future__ import annotations

import sys

from airlock.ai.eval import DEFAULT_DATASET, evaluate
from airlock.ai.provider import AIError, build_provider
from airlock.config import load_settings


def main() -> int:
    settings = load_settings()
    try:
        provider = build_provider(settings.ai)
    except AIError as exc:
        print(f"provider unavailable: {exc}", file=sys.stderr)
        return 2

    metrics = evaluate(provider)
    print(f"provider:  {provider.name}")
    print(f"examples:  {len(DEFAULT_DATASET)}")
    print(f"tp/fp/tn/fn: {metrics.tp}/{metrics.fp}/{metrics.tn}/{metrics.fn}")
    print(f"precision: {metrics.precision:.2f}")
    print(f"recall:    {metrics.recall:.2f}")
    print(f"f1:        {metrics.f1:.2f}")
    print(f"accuracy:  {metrics.accuracy:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
