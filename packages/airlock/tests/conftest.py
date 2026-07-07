"""Shared pytest fixtures and paths."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
MODEL_FIXTURES = FIXTURES / "model"


def _load_model_builder():
    spec = importlib.util.spec_from_file_location(
        "airlock_fixture_builder", MODEL_FIXTURES / "build_fixtures.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session", autouse=True)
def _ensure_model_fixtures() -> None:
    """Regenerate model fixtures so a fresh checkout has them available."""
    builder = _load_model_builder()
    builder.build_all()


@pytest.fixture
def model_fixtures() -> Path:
    return MODEL_FIXTURES
