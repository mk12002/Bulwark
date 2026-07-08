"""Policy profiles: strict shows everything, permissive keeps only high-signal findings."""

from __future__ import annotations

from pathlib import Path

import pytest
from bulwark_core.rules import RuleEngine
from bulwark_core.severity import Severity
from warden.policy import apply_profile, get_profile
from warden.rules import load_rules
from warden.scanner import WardenScanner


@pytest.fixture(scope="module")
def scanner() -> WardenScanner:
    return WardenScanner(RuleEngine(load_rules()))


def test_unknown_profile_raises() -> None:
    with pytest.raises(ValueError):
        get_profile("nonsense")


def test_profiles_are_monotonic(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "basic.yaml"))
    strict = apply_profile(result, get_profile("strict"))
    balanced = apply_profile(result, get_profile("balanced"))
    permissive = apply_profile(result, get_profile("permissive"))
    # Tightening the profile can only remove findings, never add them.
    assert len(strict.findings) >= len(balanced.findings) >= len(permissive.findings)
    # Strict never drops anything.
    assert len(strict.findings) == len(result.findings)


def test_permissive_drops_low_severity(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "basic.yaml"))
    permissive = apply_profile(result, get_profile("permissive"))
    assert all(f.severity >= Severity.MEDIUM for f in permissive.findings)
    assert all(f.confidence in {"medium", "high"} for f in permissive.findings)


def test_suppressed_count_recorded(scanner: WardenScanner, fixtures: Path) -> None:
    result = scanner.scan(str(fixtures / "over_privileged" / "basic.yaml"))
    permissive = apply_profile(result, get_profile("permissive"))
    assert permissive.meta["policy_profile"] == "permissive"
    dropped = len(result.findings) - len(permissive.findings)
    if dropped:
        assert permissive.meta["policy_suppressed"] == dropped
