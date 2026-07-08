"""Nox sessions for the Bulwark workspace (optional; `python check.py` needs no nox).

    nox            # lint + type + test across every package
    nox -s test    # just the test suite
    nox -s lint

Each session iterates the packages and runs the tool from the package directory so the
per-package config is honored.
"""

from __future__ import annotations

import nox

PACKAGES = ["bulwark-core", "airlock", "warden", "manifest", "bulwark"]
IMPORT_DIR = {"bulwark-core": "bulwark_core"}
nox.options.sessions = ["lint", "type", "test"]


@nox.session
def lint(session: nox.Session) -> None:
    session.install("ruff")
    for pkg in PACKAGES:
        session.run("ruff", "check", ".", external=True)


@nox.session
def type(session: nox.Session) -> None:  # noqa: A001 - session name is intentional
    session.install("mypy")
    for pkg in PACKAGES:
        with session.chdir(f"packages/{pkg}"):
            session.run("mypy", IMPORT_DIR.get(pkg, pkg))


@nox.session
def test(session: nox.Session) -> None:
    for pkg in PACKAGES:
        with session.chdir(f"packages/{pkg}"):
            session.install("-e", ".[dev]")
            session.run("pytest", "-q")
