"""Architectural invariant tests.

These assert properties of the *codebase* rather than of any behaviour. Both
invariants below were previously enforced only by discipline and a grep in the
documentation — and an architectural invariant that depends on everyone remembering
is an invariant with a half-life.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[1] / "bulwark_core"
SUITE_PACKAGES = {"airlock", "warden", "manifest", "bulwark"}


def _core_modules() -> list[Path]:
    return sorted(p for p in CORE_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def _imported_roots(source: str) -> set[str]:
    """Top-level module names imported by a source file, at any nesting depth."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_core_imports_nothing_from_the_suite() -> None:
    """``bulwark-core`` depends on nothing else in the suite; the tools depend on it.

    This one-way dependency is what keeps each package independently installable and
    lets core validate tool-owned data — taxonomy codes — that it can never import.
    The moment core imports a tool you get a cycle, and the "one spine, three tools"
    architecture collapses.
    """
    violations: list[str] = []
    for module in _core_modules():
        offenders = _imported_roots(module.read_text(encoding="utf-8")) & SUITE_PACKAGES
        if offenders:
            violations.append(f"{module.relative_to(CORE_ROOT)}: imports {sorted(offenders)}")
    assert not violations, "bulwark-core must not import suite packages:\n  " + "\n  ".join(
        violations
    )


def test_core_never_executes_what_it_inspects() -> None:
    """Inspection only — a regression here is a top-severity bug (see SECURITY.md).

    ``yaml.load`` can instantiate arbitrary Python objects, which is structurally the
    same vulnerability as ``pickle.load`` in a different syntax; a rule pack is
    untrusted input, so only ``safe_load`` is permitted.
    """
    banned = {
        "pickle.load": "pickle.load(",
        "pickle.loads": "pickle.loads(",
        "torch.load": "torch.load(",
        "joblib.load": "joblib.load(",
        "yaml.load": "yaml.load(",
        "eval": " eval(",
        "exec": " exec(",
    }
    violations: list[str] = []
    for module in _core_modules():
        text = module.read_text(encoding="utf-8")
        for label, needle in banned.items():
            if needle in text and "safe_load" not in needle:
                violations.append(f"{module.relative_to(CORE_ROOT)}: uses {label}")
    assert not violations, "core must never execute its input:\n  " + "\n  ".join(violations)


@pytest.mark.parametrize("module_name", ["findings", "severity", "signals", "limits"])
def test_core_hot_modules_have_no_third_party_imports(module_name: str) -> None:
    """The data model and bounds must stay importable with a minimal dependency set."""
    source = (CORE_ROOT / f"{module_name}.py").read_text(encoding="utf-8")
    roots = _imported_roots(source)
    allowed = {
        "__future__",
        "abc",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "os",
        "pathlib",
        "typing",
        "pydantic",  # the declared data-model dependency
        "bulwark_core",
    }
    unexpected = sorted(roots - allowed)
    assert not unexpected, f"{module_name}.py imports unexpected modules: {unexpected}"
