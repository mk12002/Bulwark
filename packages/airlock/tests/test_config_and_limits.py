"""Regression tests for configuration layering and hostile-input bounds.

The TOML merge previously read ``airlock.toml``, parsed it, and then discarded every
value — so the documented ways to enable AI enrichment and configure waivers silently
did nothing. These tests pin both the layering and its precedence.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bulwark_core.severity import Severity

from airlock.config import load_settings
from airlock.scanners.model.loader import resolve


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "airlock.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_toml_values_are_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AIRLOCK_FAIL_ON", raising=False)
    cfg = _write(
        tmp_path,
        'fail_on = "critical"\n'
        'output_format = "json"\n'
        "strict_allowlist = true\n"
        'suppress_rules = ["M4-*"]\n'
        "[ai]\n"
        "enabled = true\n"
        "max_findings_to_enrich = 5\n",
    )
    settings = load_settings(cfg)
    assert settings.fail_on is Severity.CRITICAL
    assert settings.output_format == "json"
    assert settings.strict_allowlist is True
    assert settings.suppress_rules == ["M4-*"]
    assert settings.ai.enabled is True
    assert settings.ai.max_findings_to_enrich == 5


def test_environment_overrides_the_toml_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Env is the operator's channel; a committed file must not weaken a pipeline."""
    cfg = _write(tmp_path, 'fail_on = "critical"\n')
    monkeypatch.setenv("AIRLOCK_FAIL_ON", "low")
    assert load_settings(cfg).fail_on is Severity.LOW


def test_defaults_hold_with_no_file_and_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AIRLOCK_FAIL_ON", "AIRLOCK_OUTPUT_FORMAT", "AIRLOCK_STRICT_ALLOWLIST"):
        monkeypatch.delenv(var, raising=False)
    settings = load_settings(Path("does-not-exist.toml"))
    assert settings.fail_on is Severity.HIGH
    assert settings.output_format == "terminal"
    assert settings.ai.enabled is False


def test_ai_config_has_no_api_key_field() -> None:
    """A key must have nowhere to live on disk; env (AIRLOCK_AI_API_KEY) is the only channel."""
    from bulwark_core.config import AIConfig

    assert "api_key" not in AIConfig.model_fields


def test_local_resolve_does_not_follow_symlinks_out_of_root(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "model.safetensors").write_bytes(b"\x08\x00\x00\x00\x00\x00\x00\x00{}")
    (outside / "secret.bin").write_bytes(b"x")
    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted in this environment")

    names = {f.relpath for f in resolve(str(root)).files}
    assert "model.safetensors" in names
    assert not any("secret.bin" in n for n in names)
