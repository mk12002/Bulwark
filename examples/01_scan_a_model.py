#!/usr/bin/env python
"""Scan a model artifact from Python and act on the findings.

    python examples/01_scan_a_model.py [PATH_OR_HF_TARGET]

The scanner never loads the model: pickles are disassembled with ``pickletools``,
configs are parsed as JSON, archives are read from the central directory. Nothing in
the artifact is executed at any point.

Requires: pip install "airlock[model]"
"""

from __future__ import annotations

import sys

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner
from bulwark_core.severity import Severity

DEFAULT_TARGET = "packages/airlock/fixtures/model/poisoned"


def main(target: str = DEFAULT_TARGET) -> int:
    # The rule engine is injected, not constructed inside the scanner — so you can
    # supply your own rule packs (see 06_custom_rule_pack.py) or a subset for testing.
    scanner = ModelScanner(RuleEngine(load_rules()))

    # strict=True additionally flags pickle imports from modules outside the ML
    # allowlist (Fickling-style). Higher recall, calibrated for the HF ecosystem.
    # scanner = ModelScanner(RuleEngine(load_rules()), strict=True)

    result = scanner.scan(target)

    print(f"target        : {result.target}")
    print(f"worst severity: {result.worst().value}")
    print(f"findings      : {len(result.findings)}\n")

    for f in result.sorted_findings():
        print(f"  [{f.severity.value:8}] {f.category:3} {f.id}")
        print(f"             where: {f.location.path or '-'}")
        print(f"             why  : {f.rationale.strip().splitlines()[0]}")
        print(f"             fix  : {f.remediation.strip().splitlines()[0]}\n")

    # exit_code() is the CI contract: non-zero when anything reaches the threshold.
    # A real gate would `raise SystemExit(result.exit_code(...))`; this example reports
    # the decision instead so it can be run without appearing to fail.
    for threshold in (Severity.CRITICAL, Severity.HIGH, Severity.LOW):
        gate = result.exit_code(threshold)
        verdict = "FAIL" if gate else "pass"
        print(f"  --fail-on {threshold.value:8} -> exit {gate} ({verdict})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
