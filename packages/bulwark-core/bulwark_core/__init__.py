"""bulwark-core — the shared spine for the Bulwark security stack.

This package will host the tool-agnostic machinery that Airlock, Warden, and
Manifest all reuse:

- ``findings``  — ``Severity``, ``Location``, ``Finding``, ``ScanResult`` (pydantic v2)
- ``taxonomy``  — a category registry (``register_categories``) each tool extends
- ``rules``     — the YAML rule-pack schema, loader, ``lint``, and signal matcher
- ``severity``  — ``worst()`` / ``exit_code(threshold)`` scoring
- ``scanner``   — the abstract ``Scanner`` (resolve → analyze → rules → ScanResult)
- ``report``    — terminal / json / html / sarif renderers
- ``ai``        — the provider protocol (ollama / openai_compat / anthropic) + enrich

It is currently a skeleton. The spine is extracted out of Airlock (which today holds
a working copy under ``airlock.core``) as **step 1 of the Warden build**, per the
migration checklist in the repo-root ``BULWARK.md`` — extracting a shared library is
done once a second consumer (Warden) exists to validate the abstraction, so the API
is not over-fitted to Airlock alone.

Invariant: bulwark-core depends on nothing else in the suite; the tools depend on it.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
