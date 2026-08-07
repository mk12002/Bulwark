"""The shared stderr console.

Every diagnostic the suite emits — warnings, AI notes, log records — goes to stderr,
because stdout carries the report and is routinely redirected:

    airlock scan model X --format json > out.json

A single stray byte on stdout corrupts that document. Keeping one console object here
rather than constructing ``Console(stderr=True)`` in four CLIs means the decision is
made once, and a future change (colour policy, width, quiet mode) applies everywhere.
"""

from __future__ import annotations

from functools import lru_cache

from rich.console import Console

__all__ = ["err_console"]


@lru_cache(maxsize=1)
def err_console() -> Console:
    """Return the process-wide stderr console (created once)."""
    return Console(stderr=True)
