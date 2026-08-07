"""Every example in examples/ must actually run.

Documentation that does not execute rots silently: an API rename leaves the README
looking authoritative while the code no longer works. Running them in CI means an
example is as maintained as the code it demonstrates.

They run from the repository root because they reference the bundled fixtures by
relative path — which is also how a reader will run them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = REPO_ROOT / "examples"


def _scripts() -> list[Path]:
    return sorted(EXAMPLES.glob("[0-9]*.py"))


def test_examples_directory_is_not_empty() -> None:
    assert _scripts(), "examples/ has no runnable scripts"


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.stem)
def test_example_runs_cleanly(script: Path) -> None:
    """Exit 0, no traceback, and something printed."""
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"{script.name} exited {proc.returncode}\n{proc.stderr[-2000:]}"
    assert "Traceback" not in proc.stderr, f"{script.name} raised:\n{proc.stderr[-2000:]}"
    assert proc.stdout.strip(), f"{script.name} printed nothing"


def test_examples_are_documented() -> None:
    """Each script is listed in examples/README.md, so the index cannot drift."""
    readme = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    missing = [s.name for s in _scripts() if s.name not in readme]
    assert not missing, f"undocumented examples: {missing}"


def test_examples_do_not_write_into_the_repository() -> None:
    """An example must not leave artifacts in a reader's checkout."""
    before = {p for p in REPO_ROOT.glob("*") if p.is_file()}
    subprocess.run(
        [sys.executable, str(EXAMPLES / "03_generate_an_ai_bom.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    after = {p for p in REPO_ROOT.glob("*") if p.is_file()}
    assert after == before, f"example wrote into the repo root: {sorted(after - before)}"
