"""Structured logging for the suite — diagnostics, never report output.

Two hard rules, both load-bearing:

**1. Logs go to stderr. Always.** Stdout carries the report, and a scan is routinely
piped: ``airlock scan model X --format json > out.json``. A single log line on stdout
corrupts that JSON and breaks every downstream consumer. The handler is pinned to
stderr and there is no option to change it.

**2. A library emits nothing unless the application asks.** Importing ``airlock`` must
not configure global logging or print anything — that is the application's decision.
Loggers carry a ``NullHandler`` until :func:`configure` is called, which the CLIs do
once, from ``-v``/``-vv``.

Content warning for anyone adding a log call: much of what flows through this codebase
is attacker-controlled (tool descriptions, embedded pickle strings, archive member
names). Log *facts* at INFO — counts, durations, decisions — and keep raw artifact
content at DEBUG, where :func:`safe` truncates it and strips newlines so a hostile
artifact cannot forge log lines or flood a terminal.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from time import perf_counter

__all__ = ["configure", "get_logger", "safe", "timed"]

_ROOT = "bulwark"
_CONFIGURED = False

# Attacker-controlled text is truncated before it can reach a log line.
MAX_LOG_VALUE = 200


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger that is silent until :func:`configure` runs.

    ``name`` is usually ``__name__``; the ``bulwark.`` prefix is added so one call to
    :func:`configure` controls every logger in the suite without touching the root
    logger (which belongs to the embedding application, not to us).
    """
    logger = logging.getLogger(f"{_ROOT}.{name}")
    if not logger.handlers and not _CONFIGURED:
        logger.addHandler(logging.NullHandler())
    return logger


def configure(verbosity: int = 0, *, force: bool = False) -> None:
    """Attach a stderr handler to the ``bulwark`` logger tree.

    ``verbosity`` maps 0 → WARNING, 1 → INFO, 2+ → DEBUG, matching ``-v``/``-vv``.
    Idempotent unless ``force``, so a library caller that configures logging once is
    not overridden by a nested CLI invocation.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    level = {0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)
    logger = logging.getLogger(_ROOT)
    logger.handlers.clear()

    handler: logging.Handler
    try:  # rich is a dependency of every tool, but degrade cleanly if absent
        from rich.logging import RichHandler

        from bulwark_core.report.console import err_console

        handler = RichHandler(
            console=err_console(),
            show_path=verbosity >= 2,
            show_time=verbosity >= 2,
            rich_tracebacks=True,
            markup=False,  # log text may be attacker-derived; never interpret markup
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    except Exception:  # pragma: no cover - fallback path
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    handler.setLevel(level)
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False  # never leak into the application's root logger
    _CONFIGURED = True


def safe(value: object, limit: int = MAX_LOG_VALUE) -> str:
    """Render a value for logging: collapsed to one line and truncated.

    Use this for anything derived from a scanned artifact. Newlines are collapsed so a
    crafted tool description cannot forge additional log lines, and the length cap
    keeps a hostile artifact from flooding a terminal or a CI log.
    """
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit] + "…"


@contextmanager
def timed(logger: logging.Logger, what: str) -> Iterator[None]:
    """Log the duration of a block at DEBUG. Timing is diagnostic, never a finding."""
    start = perf_counter()
    try:
        yield
    finally:
        logger.debug("%s took %.3fs", what, perf_counter() - start)
