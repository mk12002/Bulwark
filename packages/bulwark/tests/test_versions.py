"""Suite-wide packaging invariants.

Five packages release together from one tag, so their versions must agree — and each
package's ``__version__`` must match its ``pyproject.toml``. That pair drifts silently:
the wheel reports one version, ``bulwark version`` reports another, and nothing fails
until someone tries to reproduce a scan from a version string in a report.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES = {
    "bulwark-core": "bulwark_core",
    "airlock": "airlock",
    "warden": "warden",
    "manifest": "manifest",
    "bulwark": "bulwark",
}


def _declared_version(pkg: str) -> str:
    data = tomllib.loads((REPO_ROOT / "packages" / pkg / "pyproject.toml").read_text("utf-8"))
    return str(data["project"]["version"])


def _module_version(pkg: str, module: str) -> str:
    src = (REPO_ROOT / "packages" / pkg / "src" / module / "__init__.py").read_text("utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', src)
    assert match, f"{module}/__init__.py declares no __version__"
    return match.group(1)


@pytest.mark.parametrize("pkg,module", PACKAGES.items(), ids=list(PACKAGES))
def test_pyproject_and_module_versions_agree(pkg: str, module: str) -> None:
    assert _declared_version(pkg) == _module_version(pkg, module), (
        f"{pkg}: pyproject.toml and {module}.__version__ disagree — "
        "the wheel and the runtime would report different versions"
    )


def test_all_packages_share_one_version() -> None:
    """Lockstep releases: one tag publishes all five, so they must agree."""
    versions = {pkg: _declared_version(pkg) for pkg in PACKAGES}
    assert len(set(versions.values())) == 1, f"version skew across the workspace: {versions}"


def test_src_layout_is_used_everywhere() -> None:
    """Every package keeps its module under src/ so imports resolve to the installed
    wheel rather than the working directory — which is what catches a data file
    missing from the distribution."""
    for pkg, module in PACKAGES.items():
        assert (REPO_ROOT / "packages" / pkg / "src" / module).is_dir(), f"{pkg} is not src-layout"
        assert not (REPO_ROOT / "packages" / pkg / module).exists(), (
            f"{pkg}: a flat {module}/ still exists alongside src/ — imports are ambiguous"
        )


def test_every_package_declares_its_wheel_contents() -> None:
    """hatch must be told to package src/<module>, or the wheel ships empty."""
    for pkg, module in PACKAGES.items():
        text = (REPO_ROOT / "packages" / pkg / "pyproject.toml").read_text("utf-8")
        assert f'packages = ["src/{module}"]' in text, f"{pkg}: wheel packages path not set to src/"
