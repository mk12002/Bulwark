"""Shared paths for Manifest tests."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def clean_project() -> Path:
    return REPO / "fixtures" / "sample_project_clean"


@pytest.fixture
def risky_project() -> Path:
    return REPO / "fixtures" / "sample_project_risky"
