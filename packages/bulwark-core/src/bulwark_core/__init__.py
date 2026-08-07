"""bulwark-core — the shared spine for the Bulwark security stack.

Everything Airlock, Warden, and Manifest have in common lives here, and nothing
tool-specific does:

- ``findings``    — ``Severity``, ``Location``, ``Finding``, ``ScanResult`` (pydantic v2),
                    plus ``finding_key``/``dedupe``, the one definition of finding identity
- ``severity``    — the ordered severity enum, ``worst_of``, threshold parsing
- ``taxonomy``    — a category registry (``register_categories``) each tool extends
- ``signals``     — the ``Signal``/``SignalBundle`` IR between analyzers and rules
- ``rules``       — the YAML rule-pack schema, loader, predicates, and signal matcher
- ``rule_feed``   — safe installation of community rule packs
- ``scanner``     — the abstract ``Scanner`` (resolve → analyze → rules → ScanResult)
- ``config``      — ``AIConfig`` and the shared TOML/env settings layering
- ``limits``      — hostile-input caps and the bounded, symlink-contained project walk
- ``postprocess`` — waivers and baseline diffing
- ``study``       — the corpus-study harness
- ``report``      — terminal / JSON / HTML / SARIF renderers
- ``ai``          — the provider protocol (ollama / openai_compat / anthropic) + enrichment

**Invariant: bulwark-core depends on nothing else in the suite; the tools depend on
it.** That one-way dependency is what keeps each tool independently installable and
lets core validate tool-owned data (taxonomy codes) it can never import — see
``taxonomy.register_categories``.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
