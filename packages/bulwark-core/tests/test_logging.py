"""Logging invariants.

The one that matters operationally is **stdout purity**: a scan is routinely piped
(``--format json > out.json``), so a single log byte on stdout corrupts the document
and breaks every downstream consumer. That property is worth a test because the
failure is silent for the person who introduces it — their terminal looks fine.
"""

from __future__ import annotations

import io
import logging
from contextlib import redirect_stderr, redirect_stdout

from bulwark_core.logging import MAX_LOG_VALUE, configure, get_logger, safe


def _reset() -> None:
    """Detach handlers so each test configures from a known state."""
    import bulwark_core.logging as mod

    logging.getLogger("bulwark").handlers.clear()
    mod._CONFIGURED = False


def _flat(text: str) -> str:
    """Collapse whitespace — rich word-wraps to the console width, so raw substring
    assertions on rendered output are brittle."""
    return " ".join(text.split())


def test_logging_never_writes_to_stdout() -> None:
    """The core contract: diagnostics go to stderr so stdout stays machine-readable."""
    _reset()
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        configure(verbosity=2, force=True)
        get_logger("test").warning("marker-stdout-purity")
    assert out.getvalue() == ""
    assert "marker-stdout-purity" in _flat(err.getvalue())


def test_library_import_is_silent_until_configured() -> None:
    """A library must not emit anything until the application opts in."""
    _reset()
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        get_logger("quiet").info("should be swallowed by the NullHandler")
    assert out.getvalue() == ""
    assert err.getvalue() == ""


def test_verbosity_maps_to_levels() -> None:
    """-v is INFO, -vv is DEBUG, bare is WARNING."""
    for verbosity, expected in ((0, logging.WARNING), (1, logging.INFO), (2, logging.DEBUG)):
        _reset()
        configure(verbosity=verbosity, force=True)
        assert logging.getLogger("bulwark").level == expected


def test_configure_is_idempotent_without_force() -> None:
    """A nested CLI call must not stomp an embedding application's configuration."""
    _reset()
    configure(verbosity=2, force=True)
    configure(verbosity=0)  # no force — must be ignored
    assert logging.getLogger("bulwark").level == logging.DEBUG


def test_does_not_propagate_to_root_logger() -> None:
    """Bulwark's records must not leak into the host application's root logger."""
    _reset()
    configure(verbosity=1, force=True)
    assert logging.getLogger("bulwark").propagate is False


def test_safe_collapses_newlines_so_hostile_text_cannot_forge_log_lines() -> None:
    """Artifact-derived text is single-lined before it can reach a log record."""
    forged = "harmless\nINFO     scan completed with no findings"
    assert "\n" not in safe(forged)
    assert "harmless INFO" in safe(forged)


def test_safe_truncates_so_a_hostile_artifact_cannot_flood_a_log() -> None:
    rendered = safe("A" * 5000)
    assert len(rendered) <= MAX_LOG_VALUE + 1  # +1 for the ellipsis
    assert rendered.endswith("…")
