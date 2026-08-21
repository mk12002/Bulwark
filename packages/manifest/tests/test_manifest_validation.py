"""Lock the published Manifest validation results against regression.

``docs/VALIDATION.md`` publishes four measurements. These tests make each an executable
invariant, so a discoverer or BOM-rendering change that moves a published figure fails CI
instead of quietly making the docs wrong.

The studies live in ``scripts/study.py`` and are loaded by path. All of it runs with
``offline=True``: no network, and nothing in the target project is executed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_STUDY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "study.py"


def _load_study() -> Any:
    spec = importlib.util.spec_from_file_location("manifest_study", _STUDY_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: @dataclass resolves field types via sys.modules[cls.__module__].
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def study() -> Any:
    return _load_study()


# --------------------------------------------------------------------------- #
# 1. Discovery recall
# --------------------------------------------------------------------------- #


def test_discovery_recall_is_total(study: Any) -> None:
    """Published: 15/15. A silent inventory gap is the worst failure mode here."""
    rows, _types = study.study_recall()
    for r in rows:
        assert not r.missed, f"{r.project}: no longer discovering {sorted(r.missed)}"
        assert r.recall == 1.0


def test_embedded_components_are_still_discovered(study: Any) -> None:
    """The substantive claim: most real components are not in requirements.txt.

    A dependency scanner reading only requirements.txt would find 3 of these 11.
    """
    _rows, types = study.study_recall()
    risky = types["sample_project_risky"]

    assert risky["torch"] == "library", "notebook !pip install line no longer discovered"
    assert risky["datasets"] == "library"
    assert risky["google/flan-t5-small"] == "machine-learning-model", "from_pretrained() lost"
    assert risky["imdb"] == "data", "load_dataset() reference lost"
    assert risky["system_prompt"] == "data", "embedded agent prompt lost"


# --------------------------------------------------------------------------- #
# 2. BOM conformance
# --------------------------------------------------------------------------- #


def test_both_bom_formats_are_structurally_conformant(study: Any) -> None:
    """Published: 10/10. 'Standards-based' is the project's most-repeated claim."""
    rows = study.study_conformance()
    failed = [f"{r.check}: {r.detail}" for r in rows if not r.passed]
    assert not failed, "BOM conformance regressed:\n" + "\n".join(failed)
    assert len(rows) >= 10, "conformance checks were removed rather than fixed"


# --------------------------------------------------------------------------- #
# 3. Governance coverage
# --------------------------------------------------------------------------- #


def test_every_finding_maps_to_a_control(study: Any) -> None:
    """A B-code with no control mapping is orphaned from the governance view."""
    _gov, per_code = study.study_governance()
    orphaned = [code for code, _n, mapped in per_code if not mapped]
    assert not orphaned, f"B-codes with no control mapping: {orphaned}"


def test_process_only_controls_are_mapped_but_honestly_empty(study: Any) -> None:
    """NIST MANAGE and EU Art.14 are organizational process.

    A static scan has nothing to say about either. They stay mapped so the gap is visible
    in the report — but claiming coverage there would be manufacturing evidence.
    """
    gov, _per_code = study.study_governance()
    by_name = {g.framework: g for g in gov}
    assert by_name["NIST AI RMF"].exercised == 3, "NIST coverage changed — verify MANAGE"
    assert by_name["EU AI Act"].exercised == 5, "EU coverage changed — verify Art.14"


# --------------------------------------------------------------------------- #
# 4. Risk-bridge fidelity
# --------------------------------------------------------------------------- #


def test_bridging_is_purely_additive(study: Any) -> None:
    """Published: 6/6. The failure modes are silent drop and double-counting."""
    rows = study.study_bridge()
    failed = [f"{r.metric}: {r.value}" for r in rows if not r.ok]
    assert not failed, "risk-bridge fidelity regressed:\n" + "\n".join(failed)
