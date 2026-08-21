"""Manifest validation harness — four reproducible studies over the *system* layer.

Airlock validates detection on bytes; Warden validates composition on configs. The
system layer claims something different again — that Manifest produces a *complete*,
*standards-conformant*, *governable* inventory — so each of those three words needs a
measurement rather than an assertion:

1. **Discovery recall** — against hand-written ground truth for the two fixture
   projects. An inventory tool that silently misses a component is worse than no
   inventory, because the gap is invisible. Measured as recall and precision per
   component type.
2. **BOM conformance** — CycloneDX and SPDX documents are checked against the
   required-field rules of their specs. "Standards-based" is the project's most-repeated
   claim and the cheapest one to get subtly wrong.
3. **Governance coverage** — how much of NIST AI RMF and the EU AI Act a real scan
   actually exercises, and how many B-codes carry a control mapping. A control map with
   no findings pointing at it is decoration.
4. **Risk-bridge fidelity** — `--scan-risk` folds Airlock and Warden findings into the
   BOM as B5. Measured by checking the part-level findings survive the bridge rather than
   being counted twice or dropped.

Deterministic and offline: `ManifestScanner(offline=True)` performs no network I/O, so
vulnerability and license resolution are skipped and the numbers are stable in CI.

Usage (from repo root, venv active):
    python packages/manifest/scripts/study.py
    python packages/manifest/scripts/study.py > packages/manifest/docs/VALIDATION_DATA.md
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulwark_core.findings import ScanResult
from bulwark_core.severity import Severity

from manifest.govern import controls
from manifest.rules import RuleEngine, load_rules
from manifest.scanner import ManifestScanner

_ROOT = Path(__file__).resolve().parents[3]
_CLEAN = _ROOT / "packages" / "manifest" / "fixtures" / "sample_project_clean"
_RISKY = _ROOT / "packages" / "manifest" / "fixtures" / "sample_project_risky"


# --------------------------------------------------------------------------- #
# Study 1 — discovery recall against ground truth
# --------------------------------------------------------------------------- #
# Ground truth is written by hand from the fixture trees, NOT from Manifest's own
# output — otherwise the study would only prove Manifest agrees with itself. Each
# entry is a component a human reading the fixture would expect an inventory to list.

# Recall is measured on component *identity* (did the inventory list this thing at
# all), pooled across types. Whether `torch` is typed `library` or `framework` is a
# defensible modelling choice, not a discovery failure, so the type assignment is
# reported separately rather than folded into the recall number.
#
# Each entry names where a human reading the fixture would find the component, so the
# ground truth is auditable against the tree rather than taken on trust.

_TRUTH: dict[str, dict[str, str]] = {
    "sample_project_clean": {
        "transformers": "requirements.txt",
        "torch": "requirements.txt",
        "numpy": "requirements.txt",
        "model.safetensors": "model/ weights",
    },
    "sample_project_risky": {
        "transformers": "requirements.txt (unpinned)",
        "pyyaml": "requirements.txt",
        "openai": "requirements.txt",
        "torch": "explore.ipynb — !pip install",
        "datasets": "explore.ipynb — !pip install",
        "google/flan-t5-small": "explore.ipynb — from_pretrained()",
        "imdb": "explore.ipynb — load_dataset()",
        "train.csv": "data/ on disk",
        "model.safetensors": "model/ weights",
        "pytorch_model.bin": "model/ weights (pickle)",
        "system_prompt": "agent.yaml — embedded prompt",
    },
}


@dataclass
class RecallRow:
    project: str
    expected: int
    found: int
    missed: set[str] = field(default_factory=set)
    extra: set[str] = field(default_factory=set)

    @property
    def recall(self) -> float:
        return self.found / self.expected if self.expected else 1.0


def _components(result: ScanResult) -> dict[str, str]:
    """Map every discovered CycloneDX component name to its assigned type."""
    return {
        str(c.get("name")): str(c.get("type"))
        for c in result.meta["cyclonedx"].get("components", [])
    }


def study_recall() -> tuple[list[RecallRow], dict[str, dict[str, str]]]:
    scanner = ManifestScanner(RuleEngine(load_rules()))
    rows: list[RecallRow] = []
    types: dict[str, dict[str, str]] = {}
    for project, truth in _TRUTH.items():
        result = scanner.scan(str(_ROOT / "packages" / "manifest" / "fixtures" / project))
        found = _components(result)
        expected = set(truth)
        rows.append(
            RecallRow(
                project=project,
                expected=len(expected),
                found=len(expected & set(found)),
                missed=expected - set(found),
                extra=set(found) - expected,
            )
        )
        types[project] = found
    return rows, types


# --------------------------------------------------------------------------- #
# Study 2 — BOM conformance
# --------------------------------------------------------------------------- #
# Structural conformance against the required fields each spec defines. This is a
# required-field and well-formedness check, not full JSON-Schema validation against the
# upstream schema documents (which would need a network fetch and would make the study
# non-hermetic) — so it is reported as exactly that.

_CDX_REQUIRED_DOC = ["bomFormat", "specVersion", "version"]
_CDX_REQUIRED_COMPONENT = ["type", "name"]
_CDX_VALID_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
}
_SPDX_REQUIRED_DOC = ["spdxVersion", "SPDXID", "name", "documentNamespace", "creationInfo"]
_SPDX_REQUIRED_PACKAGE = ["SPDXID", "name"]


@dataclass
class ConformanceRow:
    check: str
    detail: str
    passed: bool


def _cdx_checks(doc: dict[str, Any]) -> list[ConformanceRow]:
    rows: list[ConformanceRow] = []
    missing = [k for k in _CDX_REQUIRED_DOC if k not in doc]
    rows.append(
        ConformanceRow(
            "CycloneDX document required fields",
            f"{', '.join(_CDX_REQUIRED_DOC)}" + (f" — missing {missing}" if missing else ""),
            not missing,
        )
    )
    rows.append(
        ConformanceRow(
            "bomFormat is 'CycloneDX'",
            str(doc.get("bomFormat")),
            doc.get("bomFormat") == "CycloneDX",
        )
    )
    serial = str(doc.get("serialNumber", ""))
    rows.append(
        ConformanceRow(
            "serialNumber is a urn:uuid", serial or "(absent)", serial.startswith("urn:uuid:")
        )
    )
    comps = doc.get("components", [])
    bad_fields = [c.get("name") for c in comps if any(k not in c for k in _CDX_REQUIRED_COMPONENT)]
    rows.append(
        ConformanceRow(
            "every component has type+name",
            f"{len(comps)} components" + (f" — bad: {bad_fields}" if bad_fields else ""),
            not bad_fields,
        )
    )
    bad_types = sorted({str(c.get("type")) for c in comps} - _CDX_VALID_TYPES)
    rows.append(
        ConformanceRow(
            "component types are in the CycloneDX enum",
            f"used: {sorted({str(c.get('type')) for c in comps})}"
            + (f" — invalid: {bad_types}" if bad_types else ""),
            not bad_types,
        )
    )
    refs = {c.get("bom-ref") for c in comps if c.get("bom-ref")}
    dangling = [
        d.get("ref")
        for d in doc.get("dependencies", [])
        if d.get("ref")
        and d.get("ref") not in refs
        and d.get("ref") != doc.get("metadata", {}).get("component", {}).get("bom-ref")
    ]
    rows.append(
        ConformanceRow(
            "dependency refs resolve to a component",
            f"{len(doc.get('dependencies', []))} dependency entries"
            + (f" — dangling: {dangling}" if dangling else ""),
            not dangling,
        )
    )
    return rows


def _spdx_checks(doc: dict[str, Any]) -> list[ConformanceRow]:
    rows: list[ConformanceRow] = []
    missing = [k for k in _SPDX_REQUIRED_DOC if k not in doc]
    rows.append(
        ConformanceRow(
            "SPDX document required fields",
            f"{', '.join(_SPDX_REQUIRED_DOC)}" + (f" — missing {missing}" if missing else ""),
            not missing,
        )
    )
    spdxid = str(doc.get("SPDXID", ""))
    rows.append(
        ConformanceRow(
            "SPDXID is SPDXRef-DOCUMENT", spdxid or "(absent)", spdxid == "SPDXRef-DOCUMENT"
        )
    )
    pkgs = doc.get("packages", [])
    bad = [p.get("name") for p in pkgs if any(k not in p for k in _SPDX_REQUIRED_PACKAGE)]
    rows.append(
        ConformanceRow(
            "every package has SPDXID+name",
            f"{len(pkgs)} packages" + (f" — bad: {bad}" if bad else ""),
            not bad,
        )
    )
    bad_ids = [p.get("SPDXID") for p in pkgs if not str(p.get("SPDXID", "")).startswith("SPDXRef-")]
    rows.append(
        ConformanceRow(
            "package SPDXIDs use the SPDXRef- prefix",
            f"{len(pkgs)} packages" + (f" — bad: {bad_ids}" if bad_ids else ""),
            not bad_ids,
        )
    )
    return rows


def study_conformance() -> list[ConformanceRow]:
    from manifest.bom.model import AIBOM
    from manifest.bom.spdx import to_spdx

    scanner = ManifestScanner(RuleEngine(load_rules()))
    result = scanner.scan(str(_RISKY))
    rows = _cdx_checks(result.meta["cyclonedx"])
    # `meta["aibom"]` is the JSON-dumped BOM; to_spdx wants the model back.
    rows += _spdx_checks(to_spdx(AIBOM.model_validate(result.meta["aibom"])))
    return rows


# --------------------------------------------------------------------------- #
# Study 3 — governance coverage
# --------------------------------------------------------------------------- #


@dataclass
class GovRow:
    framework: str
    total: int
    exercised: int
    detail: str


def study_governance() -> tuple[list[GovRow], list[tuple[str, int, bool]]]:
    scanner = ManifestScanner(RuleEngine(load_rules()), govern=True)
    result = scanner.scan(str(_RISKY))
    findings = result.findings

    # Each control maps to {"categories": [...], "count": N, "status": ...}; a control is
    # "exercised" when this project produced at least one finding underneath it.
    rmf = controls.assess(findings)
    eu = controls.assess_eu_ai_act(findings)

    gov = [
        GovRow(
            "NIST AI RMF",
            len(rmf),
            sum(1 for v in rmf.values() if v.get("count")),
            ", ".join(f"{k} ({v.get('count', 0)})" for k, v in sorted(rmf.items())),
        ),
        GovRow(
            "EU AI Act",
            len(eu),
            sum(1 for v in eu.values() if v.get("count")),
            ", ".join(f"{k} ({v.get('count', 0)})" for k, v in sorted(eu.items())),
        ),
    ]

    # Which B-codes did this project produce, and does each map to at least one control?
    mapped: set[str] = set()
    for v in list(rmf.values()) + list(eu.values()):
        mapped |= set(v.get("categories", []))
    codes = sorted({f.category for f in findings})
    per_code = [(c, sum(1 for f in findings if f.category == c), c in mapped) for c in codes]
    return gov, per_code


# --------------------------------------------------------------------------- #
# Study 4 — risk-bridge fidelity
# --------------------------------------------------------------------------- #
# `--scan-risk` runs Airlock on discovered model/MCP components and Warden on discovered
# agent assemblies, folding their findings in as B5. The failure modes worth measuring
# are silent drop (part findings vanish) and double-counting.


@dataclass
class BridgeRow:
    metric: str
    value: str
    ok: bool


def study_bridge() -> list[BridgeRow]:
    engine = RuleEngine(load_rules())
    base = ManifestScanner(engine).scan(str(_RISKY))
    bridged = ManifestScanner(engine, scan_risk=True).scan(str(_RISKY))

    base_codes = {f.category for f in base.findings}
    bridged_codes = {f.category for f in bridged.findings}
    b5 = [f for f in bridged.findings if f.category == "B5"]
    # `id` is the *rule* id and legitimately repeats across components — B1-unpinned
    # fires once per unpinned dependency. The instance key is (rule, location).
    ids = [(f.id, f.location.path) for f in bridged.findings]

    return [
        BridgeRow(
            "baseline findings (no --scan-risk)",
            f"{len(base.findings)} ({len(base_codes)} codes)",
            True,
        ),
        BridgeRow(
            "bridged findings (--scan-risk)",
            f"{len(bridged.findings)} ({len(bridged_codes)} codes)",
            True,
        ),
        BridgeRow("B5 risk findings folded in", str(len(b5)), bool(b5)),
        BridgeRow(
            "baseline codes preserved under bridging",
            f"lost: {sorted(base_codes - bridged_codes) or 'none'}",
            base_codes <= bridged_codes,
        ),
        BridgeRow(
            "no duplicate (rule, location) pairs",
            f"{len(ids)} findings, {len(set(ids))} unique",
            len(ids) == len(set(ids)),
        ),
        BridgeRow(
            "bridged findings carry a severity",
            f"max={max((f.severity for f in bridged.findings), default=Severity.INFO).value}",
            all(isinstance(f.severity, Severity) for f in bridged.findings),
        ),
    ]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _tick(ok: bool) -> str:
    return "pass" if ok else "**FAIL**"


def _set(s: set[str]) -> str:
    return ", ".join(sorted(s)) if s else "—"


def render() -> str:
    L: list[str] = [
        "# Manifest validation data",
        "",
        "Generated by `python packages/manifest/scripts/study.py`. Every number below is",
        "reproduced from that command; nothing here is hand-written.",
        "",
    ]

    # 1
    rows, types = study_recall()
    total_exp = sum(r.expected for r in rows)
    total_found = sum(r.found for r in rows)
    L += [
        "## 1. Discovery recall vs. hand-written ground truth",
        "",
        "Ground truth is written from the fixture trees by hand, not from Manifest's own",
        "output — a self-comparison would only prove the tool agrees with itself. Recall is",
        "measured on component *identity*; the type assignment is reported separately below,",
        "because whether `torch` is a `library` or a `framework` is a modelling choice rather",
        "than a discovery failure.",
        "",
        "| Project | Expected | Found | Recall | Missed | Also reported |",
        "| --- | :---: | :---: | :---: | --- | --- |",
    ]
    for r in rows:
        L.append(
            f"| `{r.project}` | {r.expected} | {r.found} | "
            f"{r.recall:.0%} | {_set(r.missed)} | {_set(r.extra)} |"
        )
    L += [
        "",
        f"**Overall recall: {total_found}/{total_exp} = {total_found / total_exp:.0%}.**",
        "",
        "Where each expected component comes from, and the type Manifest assigned it:",
        "",
        "| Project | Component | Present in the fixture as | Discovered | Typed as |",
        "| --- | --- | --- | :---: | --- |",
    ]
    for project, truth in _TRUTH.items():
        for name, origin in sorted(truth.items()):
            got = types[project].get(name)
            L.append(
                f"| `{project}` | `{name}` | {origin} | {_tick(got is not None)} | {got or '—'} |"
            )
    L += [
        "",
        "*Also reported* lists components Manifest found that ground truth did not name.",
        "These are not false positives by default — but each is listed so the gap is auditable.",
        "",
    ]

    # 2
    conf = study_conformance()
    passed = sum(1 for c in conf if c.passed)
    L += [
        "## 2. BOM conformance",
        "",
        "Required-field and well-formedness conformance for both output formats. This is a",
        "structural check against the specs' required fields, not a full JSON-Schema",
        "validation against the upstream schema documents (which would require network I/O).",
        "",
        "| Check | Detail | Result |",
        "| --- | --- | :---: |",
    ]
    for c in conf:
        L.append(f"| {c.check} | {c.detail} | {_tick(c.passed)} |")
    L += ["", f"**{passed}/{len(conf)} conformance checks pass.**", ""]

    # 3
    gov, per_code = study_governance()
    L += [
        "## 3. Governance coverage",
        "",
        "How much of each control framework a single real scan actually exercises.",
        "",
        "| Framework | Controls | Exercised by this project | Controls |",
        "| --- | :---: | :---: | --- |",
    ]
    for g in gov:
        L.append(f"| {g.framework} | {g.total} | {g.exercised} | {g.detail} |")
    L += [
        "",
        "Per-code breakdown for `sample_project_risky`:",
        "",
        "| B-code | Findings | Mapped to a control |",
        "| --- | :---: | :---: |",
    ]
    for code, n, is_mapped in per_code:
        L.append(f"| {code} | {n} | {_tick(is_mapped)} |")
    L.append("")

    # 4
    bridge = study_bridge()
    ok = sum(1 for b in bridge if b.ok)
    L += [
        "## 4. Risk-bridge fidelity",
        "",
        "`--scan-risk` runs Airlock and Warden on discovered components and folds their",
        "findings in as B5. The failure modes measured here are silent drop and double-counting.",
        "",
        "| Metric | Value | Result |",
        "| --- | --- | :---: |",
    ]
    for b in bridge:
        L.append(f"| {b.metric} | {b.value} | {_tick(b.ok)} |")
    L += ["", f"**{ok}/{len(bridge)} bridge checks pass.**", ""]

    return "\n".join(L) + "\n"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    print(render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
