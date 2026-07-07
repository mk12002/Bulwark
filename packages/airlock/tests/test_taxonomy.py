"""Tests for the risk taxonomy."""

from __future__ import annotations

from airlock.taxonomy import (
    Category,
    all_categories,
    categories_for,
    category_info,
)
from bulwark_core.severity import Severity


def test_all_categories_present() -> None:
    codes = {c.code for c in all_categories()}
    expected = {Category(f"M{i}") for i in range(1, 8)} | {Category(f"P{i}") for i in range(1, 10)}
    assert codes == expected


def test_category_info_by_string_and_enum() -> None:
    by_str = category_info("M1")
    by_enum = category_info(Category.M1)
    assert by_str == by_enum
    assert by_str.default_severity == Severity.CRITICAL
    assert by_str.target == "model"
    assert "CWE-502" in by_str.references


def test_categories_for_target() -> None:
    model = categories_for("model")
    mcp = categories_for("mcp")
    assert len(model) == 7
    assert len(mcp) == 9
    assert all(c.target == "model" for c in model)
    assert all(c.target == "mcp" for c in mcp)


def test_p1_is_mcp_and_high() -> None:
    info = category_info("P1")
    assert info.target == "mcp"
    assert info.default_severity == Severity.HIGH
