#!/usr/bin/env python
"""Add a detection without touching any Python — the point of YAML rule packs.

    python examples/05_custom_rule_pack.py

Detection *policy* lives in YAML; evidence *gathering* lives in typed Python. That
split is why a security researcher can contribute a rule without reading the scanner,
and why adding a discoverer later picks up every existing rule for free.

A rule matches one **signal** — the intermediate representation analyzers emit. Run
``airlock rules debug model <target>`` to see every signal available for a target, and
``airlock rules lint`` to have a typo'd signal name rejected rather than silently
producing a rule that never fires.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner

CUSTOM_PACK = """
version: 1
target: model
rules:
  # A realistic organisation policy: "no pickle-serialized weights in production,
  # regardless of payload". The built-in M4 is a MEDIUM advisory because it has to
  # suit everyone; a local pack can raise it to a blocker for your estate.
  - id: LOCAL-no-pickle-in-production
    category: M4
    title: "Pickle-serialized weights violate the local no-pickle policy"
    severity: high
    confidence: high
    match:
      signal: model.pickle_file
      predicate: non_empty
    rationale: >-
      Internal policy PLT-014 requires safetensors for all production model artifacts.
      Pickle permits code execution on load even when no payload is present today, and
      the artifact may be re-published at any time.
    remediation: >-
      Convert with `safetensors.torch.save_file`, or request an exception in PLT-014.
    references: ["CWE-502"]

  # Platform-module imports are never legitimate in model weights. This is a local
  # tightening of the built-in M1 denylist.
  - id: LOCAL-platform-module-import
    category: M3
    title: "Pickle imports a platform/OS module"
    severity: critical
    confidence: high
    match:
      signal: pickle.imports
      pattern: "^(nt|posix|os|subprocess)\\\\."
    rationale: >-
      Model weights have no legitimate reason to import an OS module. This is a local
      tightening of the built-in denylist for our estate.
    remediation: >-
      Quarantine the artifact and notify the platform security team.
    references: ["CWE-502"]
"""


def main() -> int:
    user_rules = Path(tempfile.mkdtemp()) / "rules" / "model"
    user_rules.mkdir(parents=True)
    (user_rules / "local_policy.yaml").write_text(CUSTOM_PACK, encoding="utf-8")

    # extra_roots *appends* to the packaged + user roots, so built-in detections still
    # apply. A duplicate rule id across roots is a hard error rather than a silent
    # override — a local pack cannot disable a built-in rule by redefining it.
    engine = RuleEngine(load_rules(extra_roots=[user_rules.parent]))
    result = ModelScanner(engine).scan("packages/airlock/fixtures/model/poisoned")

    local = [f for f in result.findings if f.id.startswith("LOCAL-")]
    print(f"local policy rules fired {len(local)} time(s):")
    for f in local:
        print(f"  [{f.severity.value:8}] {f.id}")
        print(f"             {f.evidence}")

    builtin = len(result.findings) - len(local)
    print(f"\n{builtin} built-in finding(s) still apply — local packs add, never replace.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
