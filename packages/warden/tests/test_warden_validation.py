"""Lock the published Warden validation results against regression.

``docs/VALIDATION.md`` publishes four measurements. Numbers in a document rot silently;
these tests make each one an executable invariant, so a lexicon or rule change that moves
a published figure fails CI instead of quietly making the docs wrong.

The studies live in ``scripts/study.py`` and are loaded by path — the package itself
ships no study code. Everything is deterministic and offline: no network, nothing
executed, all tool "capabilities" are inert strings in a config.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_STUDY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "study.py"


def _load_study() -> Any:
    spec = importlib.util.spec_from_file_location("warden_study", _STUDY_PATH)
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
# 1. Cross-framework invariance
# --------------------------------------------------------------------------- #


def test_every_importer_recovers_the_same_assembly(study: Any) -> None:
    """The IR must abstract the framework: same agent, same capabilities, same A-codes."""
    rows, common_caps, common_codes = study.study_invariance()

    assert len(rows) == 4, "expected manifest, openai_assistant, crewai, langchain"
    first = rows[0]
    for row in rows:
        assert row.caps == first.caps, f"{row.importer} recovered different capabilities"
        assert row.codes == first.codes, f"{row.importer} produced different A-codes"
        assert row.a2, f"{row.importer} lost the A2 toxic combination"

    assert common_caps == {"browse", "net_out", "secret_read"}
    assert "A2" in common_codes


# --------------------------------------------------------------------------- #
# 2. Lexicon robustness — the published 3/7, and *which* 3
# --------------------------------------------------------------------------- #

# Locking the specific variants matters more than the ratio: a change that fixes one
# naming convention while breaking another would keep 4/7 and still be a regression.
_EXPECTED_A2 = {"explicit", "snake_case_only", "camelCase_only", "opaque_names_rich_desc"}


def test_lexicon_robustness_matches_published_result(study: Any) -> None:
    rows = {r.variant: r for r in study.study_lexicon()}
    caught = {name for name, r in rows.items() if r.a2}

    assert caught == _EXPECTED_A2, (
        "the published 4/7 lexicon result changed — update docs/VALIDATION.md and "
        "docs/EMPIRICAL_VALIDATION.md if this is intentional"
    )


def test_explicit_kill_chain_is_critical(study: Any) -> None:
    """The baseline case must stay CRITICAL: untrusted input + secret + egress."""
    rows = {r.variant: r for r in study.study_lexicon()}
    assert rows["explicit"].max_sev == "critical"


def test_naming_convention_does_not_change_the_verdict(study: Any) -> None:
    """snake_case and camelCase must classify identically.

    Regression guard for a real defect the study surfaced: `_tool_text` de-snaked
    `_`/`-` but not case transitions, so `browseWeb` was unclassifiable and every
    camelCase assembly — most of the TypeScript MCP ecosystem — silently lost A2
    while still reporting a clean-looking MEDIUM verdict.
    """
    rows = {r.variant: r for r in study.study_lexicon()}
    snake, camel = rows["snake_case_only"], rows["camelCase_only"]

    assert camel.caps == snake.caps, "camelCase and snake_case classify differently again"
    assert camel.a2 and snake.a2, "the kill chain must surface under both conventions"
    assert camel.max_sev == snake.max_sev == "critical"


# --------------------------------------------------------------------------- #
# 3. False positives
# --------------------------------------------------------------------------- #


def test_no_benign_agent_is_told_it_has_an_exfil_path(study: Any) -> None:
    """The flagship compositional claim: zero spurious A2 on benign assemblies."""
    rows = study.study_false_positives()
    spurious = [r.agent for r in rows if r.a2]
    assert not spurious, f"spurious A2 on benign agents: {spurious}"


def test_documented_lexicon_regressions_stay_fixed(study: Any) -> None:
    """Verbs that are only risky next to a domain noun must stay bounded.

    Each of these was a real spurious classification the FP study surfaced:
      - `format_response`  -> DESTRUCTIVE ("format" a string, not a disk)
      - `translate_text`   -> FINANCIAL   ("transfer" meaning, not money)
      - `query_user`       -> NET_OUT     ("request" as ordinary English)
    All three are HIGH_IMPACT or egress capabilities, so each one also produced a
    spurious A3 missing-gate finding on a completely benign tool.
    """
    rows = {r.agent: r for r in study.study_false_positives()}

    assert rows["text_formatter"].caps == set(), "'format' is matching outside a disk context again"
    assert rows["calculator"].caps == set(), "pure arithmetic should tag no capability"
    assert rows["translator"].caps == set(), "'transfer' is matching without a money noun again"
    assert "net_out" not in rows["clarifier"].caps, "'request' is matching without network context"

    for agent in ("text_formatter", "calculator", "translator", "clarifier"):
        assert rows[agent].high_plus == 0, f"{agent}: benign agent regained a HIGH+ finding"


# --------------------------------------------------------------------------- #
# 4. Recommendation efficacy
# --------------------------------------------------------------------------- #


def test_recommend_reduces_agency_and_never_raises_it(study: Any) -> None:
    rows = study.study_recommend()
    for r in rows:
        assert r.score_after <= r.score_before, f"{r.agent}: hardening raised the agency score"
        assert r.high_after <= r.high_before, f"{r.agent}: hardening added HIGH+ findings"

    hardened = [r for r in rows if r.changes]
    assert hardened, "no fixture had anything to harden"
    mean_before = sum(r.score_before for r in hardened) / len(hardened)
    mean_after = sum(r.score_after for r in hardened) / len(hardened)
    # Published: 52.5 -> 31.2. Assert the direction and a conservative floor on the drop
    # so ordinary rule tuning does not fail CI, but a collapse in efficacy does.
    assert mean_before - mean_after >= 15.0, (
        f"recommendation efficacy dropped: {mean_before:.1f} -> {mean_after:.1f}"
    )


def test_recommend_leaves_an_already_minimal_agent_alone(study: Any) -> None:
    """A hardening pass that 'improves' a clean agent is rewriting for its own sake."""
    rows = {r.agent: r for r in study.study_recommend()}
    clean = rows["clean.yaml"]
    assert clean.changes == 0
    assert clean.score_before == clean.score_after == 0
    assert clean.residual == set()


def test_toxic_combinations_are_advised_not_silently_rewritten(study: Any) -> None:
    """Warden must not delete a tool to break A2 — that changes what the agent is for."""
    rows = {r.agent: r for r in study.study_recommend()}
    for name in ("exfil.yaml", "injectable.yaml"):
        assert "A2" in rows[name].residual, f"{name}: A2 disappeared without a human decision"
        assert rows[name].advisories > 0, f"{name}: no advisory raised for the toxic combination"
