# bulwark-core

The shared spine for the [Bulwark](../../README.md) security stack — the tool-agnostic machinery that
Airlock, Warden, and Manifest all reuse: the `Finding`/`Severity`/`ScanResult` model, the YAML rule
engine and matcher, the report renderers (terminal/JSON/HTML/SARIF), and the optional AI provider
layer.

**Status:** skeleton. A fully working copy of this spine currently lives inside Airlock at
`airlock.core` / `airlock.ai`. It is promoted into this package as **step 1 of the Warden build**,
following the migration checklist in the repo-root [`BULWARK.md`](../../BULWARK.md). Extracting the
shared library is deliberately deferred until Warden exists as a second consumer to validate the
public API, rather than over-fitting it to Airlock alone.

**Invariant:** `bulwark-core` imports nothing else in the suite. The tools depend on core; core
depends on no tool.
