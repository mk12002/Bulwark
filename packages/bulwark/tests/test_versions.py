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
# directory -> importable module name
PACKAGES = {
    "bulwark-core": "bulwark_core",
    "airlock": "airlock",
    "warden": "warden",
    "manifest": "manifest",
    "bulwark": "bulwark",
}
# directory -> PyPI distribution name. Every unnamespaced name we would have wanted
# (`airlock`, `warden`, `manifest`, `bulwark`) is already taken on PyPI by an unrelated
# project, so distributions live in the `bulwark-` namespace while the CLI commands and
# import names stay short. Publishing under a squatted name would ship our wheel to
# someone else's users, so the namespace is enforced rather than remembered.
DISTRIBUTIONS = {
    "bulwark-core": "bulwark-core",
    "airlock": "bulwark-airlock",
    "warden": "bulwark-warden",
    "manifest": "bulwark-manifest",
    "bulwark": "bulwark-suite",
}


def _declared_name(pkg: str) -> str:
    data = tomllib.loads((REPO_ROOT / "packages" / pkg / "pyproject.toml").read_text("utf-8"))
    return str(data["project"]["name"])


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


def test_distributions_stay_in_the_bulwark_namespace() -> None:
    """Never publish under a name that belongs to another project on PyPI.

    `airlock`, `warden`, `manifest`, and `bulwark` are all taken by unrelated packages.
    A rename back to any of them would either fail to publish or, worse, be typo-adjacent
    to a package our users did not ask for.
    """
    for pkg, expected in DISTRIBUTIONS.items():
        actual = _declared_name(pkg)
        assert actual == expected, (
            f"{pkg}: distribution name is {actual!r}, expected {expected!r} — "
            "the unnamespaced names are taken on PyPI by unrelated projects"
        )
        assert actual.startswith("bulwark"), f"{pkg}: {actual!r} leaves the bulwark namespace"


def test_cli_commands_stay_short_despite_namespaced_distributions() -> None:
    """The namespace is a packaging detail; `airlock scan ...` must not become
    `bulwark-airlock scan ...`."""
    for pkg, module in PACKAGES.items():
        if pkg == "bulwark-core":  # the shared spine ships no CLI
            continue
        data = tomllib.loads((REPO_ROOT / "packages" / pkg / "pyproject.toml").read_text("utf-8"))
        scripts = data["project"].get("scripts", {})
        assert module in scripts, (
            f"{pkg}: expected a `{module}` console script, got {list(scripts)}"
        )


def test_every_package_declares_its_wheel_contents() -> None:
    """hatch must be told to package src/<module>, or the wheel ships empty."""
    for pkg, module in PACKAGES.items():
        text = (REPO_ROOT / "packages" / pkg / "pyproject.toml").read_text("utf-8")
        assert f'packages = ["src/{module}"]' in text, f"{pkg}: wheel packages path not set to src/"
