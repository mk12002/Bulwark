#!/usr/bin/env python
"""One-command quality gate for the whole Bulwark workspace.

Runs ruff + mypy + pytest for every package, each from *its own directory* so the
per-package pyproject config (notably mypy's import overrides) is picked up — running
mypy from the repo root reads the wrong config and mis-reports cross-tool imports.

    python check.py            # ruff + mypy + pytest, all packages
    python check.py --fast     # ruff + pytest only (skip mypy)
    python check.py airlock    # only the named package(s)

Exit code is non-zero if any step fails; a summary table prints at the end.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGES = ["bulwark-core", "airlock", "warden", "manifest", "bulwark"]
# Import package (directory to type-check) differs from the distribution name.
# Packages use a src/ layout, so the module lives at src/<import name>.
IMPORT_DIR = {"bulwark-core": "bulwark_core"}


def import_path(pkg: str) -> str:
    """The path mypy should type-check for a package (src/ layout)."""
    return f"src/{IMPORT_DIR.get(pkg, pkg)}"


def _python() -> str:
    """The venv interpreter if present, else whatever is running this script."""
    for candidate in (ROOT / ".venv" / "Scripts" / "python.exe", ROOT / ".venv" / "bin" / "python"):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def run(label: str, args: list[str], cwd: Path) -> bool:
    print(f"\n\033[1m>> {label}\033[0m  ({cwd.name})")
    proc = subprocess.run(args, cwd=cwd)
    return proc.returncode == 0


def main() -> int:
    argv = [a for a in sys.argv[1:] if not a.startswith("-")]
    fast = "--fast" in sys.argv
    packages = [p for p in PACKAGES if not argv or p in argv]
    py = _python()

    results: list[tuple[str, str, bool]] = []
    for pkg in packages:
        pkg_dir = ROOT / "packages" / pkg
        if not pkg_dir.exists():
            continue

        results.append((pkg, "ruff", run(f"ruff {pkg}", [py, "-m", "ruff", "check", "."], pkg_dir)))
        if not fast:
            results.append(
                (pkg, "mypy", run(f"mypy {pkg}", [py, "-m", "mypy", import_path(pkg)], pkg_dir))
            )
        # bulwark-core has no dedicated test suite (exercised via the tools).
        if (pkg_dir / "tests").exists():
            results.append(
                (pkg, "pytest", run(f"pytest {pkg}", [py, "-m", "pytest", "-q"], pkg_dir))
            )

    print("\n" + "=" * 48)
    ok = True
    for pkg, step, passed in results:
        status = "\033[32mPASS\033[0m" if passed else "\033[31mFAIL\033[0m"
        print(f"  {status}  {pkg:14} {step}")
        ok = ok and passed
    print("=" * 48)
    print("all green" if ok else "FAILURES above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
