# Changelog

All notable changes to Bulwark are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Configuration files were silently ignored.** `airlock.toml` was read, parsed, and then discarded:
  the merge helper recursed into nested tables but never assigned a scalar, so `fail_on`,
  `output_format`, `strict_allowlist`, `suppress_rules`/`suppress_paths`, and `[ai].enabled` all fell
  back to defaults with no error. Settings now layer through pydantic-settings'
  `settings_customise_sources` with a TOML source ordered **below** the environment, so files work and
  env still wins. Warden and Manifest gain the same layering (`warden.toml`, `manifest.toml`), which
  they previously lacked entirely.
- **Manifest's Warden bridge skipped agent assemblies.** `--scan-risk` considered only `mcp-server`
  components, so an assembly discovered from a CrewAI crew, an OpenAI Assistants config, or an agent
  manifest was inventoried and then never audited. `agent` components are now bridged too.
- **Post-processing dropped `score` and `meta`.** Waivers and baselines rebuilt the result from an
  explicit field list, losing Warden's agency score and Manifest's entire AIBOM — which would have
  broken `--format cyclonedx` after any suppression. Now a `model_copy`, so future fields survive.
- **`--strict` did not apply to pickles embedded in numpy object arrays**, making allowlist coverage
  depend on the container rather than the payload. `serialized.py` now shares `pickle_scan`'s emitter.
- **MCP `timeout` was accepted and never used**, so a server that connected and never answered
  `initialize` hung the scan indefinitely. Enumeration is now bounded by `Limits.connect_timeout_s`
  (`AIRLOCK_LIMIT_CONNECT_TIMEOUT`), and a timeout is reported as a connect error like any other.
- **Directory walks followed symlinks and had no file cap** in both Airlock's model resolver and
  Manifest's discovery context — a target containing a link to `/` made a scan traverse the whole
  filesystem. Both now use a shared `walk_files` helper with resolved-path containment and
  `Limits.max_files` (`AIRLOCK_LIMIT_MAX_FILES`).
- **Warden lexicon false positives.** `format_response` classified as `DESTRUCTIVE` (and therefore
  high-impact, producing a spurious missing-gate finding and +10 agency score); "runs in a sandbox"
  classified as `CODE_EXEC`. Both patterns now require corroborating context.
- **A5 egress allow-listing** recognised only the literal string `allowlist`, so a genuine scope such
  as `https://api.example.com/**` was reported as unrestricted — a false positive on exactly the
  configuration the finding asks for. Concrete hosts, URL prefixes, and CIDRs now count.
- **BOM drift ignored `provenance.source`/`author`**, so a model switching publisher under the same
  name was reported as unchanged.
- **`AIBOM.add` merged more shallowly than documented** — provenance, licence, and findings from a
  later discoverer were discarded. The merge is now field-wise.
- **`noxfile.py` `lint` never changed directory**, running ruff from the repo root five times instead
  of once per package, contradicting its own docstring.

### Added
- **`airlock rules debug <kind> <target>`** — dump the signal bundle a scan produces without applying
  rules. The first question when a rule stops firing is whether the evidence exists; this answers it.
- **Signal-name validation in `rules lint`** (all three tools). A mistyped `match.signal` was the one
  rule error that failed *silently* — no rule matched, nothing errored, the detection was simply gone.
  Each tool now declares `KNOWN_SIGNALS` and lint rejects a rule referencing anything outside it.
- **`hf:org/name@revision` pinning** — pin a scan to an immutable Hub commit, so a result is
  reproducible and attributable to specific bytes rather than to a mutable branch.
- **Hugging Face purls** — models and datasets emit `pkg:huggingface/org/name@revision` in CycloneDX,
  so they are identifiable across tools and advisory feeds, not just libraries.
- **Typed SPDX relationships** — the AIBOM's own verbs (`trained-on`, `contains`, `variant-of`, …) now
  map to real SPDX relationship types instead of flattening to `DEPENDS_ON`.
- **Rug-pull detection reports added and removed tools**, not only changed ones. A tool appearing after
  approval is the classic rug-pull shape.
- **Remote MCP auth detection** — `auth.missing` now checks for credentials actually supplied (URL
  userinfo, an auth query parameter, or an `MCP_*` token env var) instead of being a synonym for
  "is remote".
- **Three-state governance status** — `ok` / `advisory` / `gap`, driven by the worst severity mapped to
  a control. A single LOW advisory no longer marks a NIST function or an EU AI Act article as a gap.
- **Risk register `owner` and `status` columns** (emitted as a template), so the output is trackable
  rather than a list of complaints.
- **AGPL is classified separately from GPL** — network copyleft is the highest-consequence licence
  term for a hosted product and is now surfaced as `restricted`.
- **Source→sink pairings are capped and rolled up** in both Airlock's P5 and Warden's A2, so a large
  tool-set produces a readable report instead of hundreds of near-duplicates.
- **`bulwark-core` test suite** — 31 tests covering severity ordering, finding identity, post-processing
  field preservation, the zip-slip guard, and the bounded walk, plus **architectural invariant tests**
  asserting that core imports nothing from the suite and never executes its input.
- **Regression suites** for the configuration layering, the Warden bridge, lexicon classification, BOM
  merging and drift, and a property test that `--recommend` actually lowers the agency score.
- **`bulwark` meta-CLI** — one front door over all three tools plus `bulwark scan` (full pipeline).
- **Airlock — format/extension-confusion detector (M6)** — sniffs magic bytes and flags a pickle
  disguised under a safe extension (the picklescan CVE-2025-10155 bypass class), then scans it anyway.
- **Airlock — allowlist mode (`--strict`, M3)** — Fickling-style: flags pickle imports from modules
  outside the ML allowlist, catching novel callables a denylist misses.
- **Warden — policy profiles** (`--profile strict|balanced|permissive`).
- **Warden — attacker-triggerable toxic flows** — escalates A2 to CRITICAL when untrusted input
  (browse / inbound) can drive a read-secret-then-exfiltrate kill chain (indirect prompt injection),
  plus an injectable-high-impact-action variant.
- **Manifest — SPDX 2.3 output, EU AI Act mapping, notebook discoverer, `manifest diff`** (BOM drift).
- **Manifest — VEX output** (`--format vex`) — CycloneDX VEX seeded from detected vulnerable deps.
- **Manifest — agent discovery + CycloneDX Agent BOM** — `agent` components (autonomy + wired tools)
  surfaced as `bulwark:agent:*` properties, aligned with the emerging CycloneDX Agent BOM.
- **Empirical validation** — a real-model corpus study, a 14-payload adversarial suite, and a
  head-to-head benchmark against picklescan / modelscan / fickling.
- **Project docs** — `USAGE.md`, `LANDSCAPE.md`, `EMPIRICAL_VALIDATION.md`, `DATASETS_AND_TESTING.md`.
- **OSS hygiene** — root `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, and a matrixed CI across all five packages.

### Security (self-hardening — the scanner ingests hostile input)
- **HTML report XSS fixed.** The report template (`report.html.j2`) fell through
  `select_autoescape(["html"])` (its `.j2` suffix), so attacker-controlled strings from a scanned
  artifact (finding evidence, file paths, MCP tool descriptions) rendered **unescaped** — opening a
  report on a hostile artifact could execute injected `<script>`/`onerror`. Autoescape is now forced on.
- **Rule-feed zip extraction hardened.** `rule_feed._extract_zip` replaced a weak `"/../"` substring
  check with a resolved-path containment guard (defeats `../` *and* absolute/drive zip-slip), and added
  per-member, total-uncompressed, and member-count caps (decompression-bomb / member-flood guards);
  members are streamed, never `zf.extract`-ed.
- **Bounded reads.** Whole-file `read_bytes()` on artifacts (numpy `.npy`, GGUF magic check, compressed
  pickles, Keras zip members) replaced with capped reads via `bulwark_core.limits.read_bounded`, so a
  crafted multi-GB file can't OOM the scanner.
- **ReDoS blast-radius bound.** Rule-engine regexes now run against a length-capped input
  (`MAX_MATCH_INPUT`) and use a compiled-pattern cache, limiting catastrophic backtracking from a
  hostile field or an untrusted community rule pack.
- **Symlink containment and a file cap on directory walks.** Both Airlock's local model resolver and
  Manifest's discovery context used `rglob`, which follows symbolic links, with no file cap — so a
  hostile artifact directory containing a link to `/` turned a scan into a filesystem traversal. Both
  now share `bulwark_core.limits.walk_files`, which resolves each entry and requires it to remain
  under the scan root (the same containment check the rule feed uses against zip-slip) and stops at
  `Limits.max_files`.
- **A time bound on MCP enumeration.** Time was the one resource dimension left unbounded: a server
  that accepted a connection and never responded hung the scan forever. Enumeration now runs under
  `anyio.fail_after(Limits.connect_timeout_s)`.
- **Prompt-injection spotlighting in the AI layer.** Content sent to a provider comes from the artifact
  being scanned and is therefore attacker-controlled. It is now fenced in `<untrusted_content>`
  markers, forged markers are stripped, and the system prompt states that the fence marks data — text
  inside it demanding a particular verdict is treated as evidence of manipulation. The layer's blast
  radius was already bounded (AI can add findings, never remove or downgrade one); this removes the
  cheapest version of the attack.
- **Honest AI budget accounting.** The executive-summary and model-card calls previously ran outside
  the `max_findings_to_enrich` counter, so the real ceiling was the documented cap plus two. All
  provider calls now share one counter.
- **A stdio-scanning warning.** `airlock scan mcp` with a command target now states that enumerating a
  stdio server *starts* it — Airlock never invokes a tool, but the server's own startup code runs with
  your privileges — and points at the fully static `airlock scan toolspec` path for CI.
- **Versioned OWASP citations.** Reference strings were a mix of 2023 and 2025 LLM Top 10 numbering
  (`LLM05` for supply chain is 2023; `LLM02`/`LLM06` were 2025). All 76 sites now carry an explicit
  edition — `OWASP:LLM03:2025` for supply chain, and so on — so a future renumbering cannot silently
  invalidate a citation. Placeholder references (`best-practice`, `license-compliance`, …) were
  replaced with real, citable sources.

### Changed (CI/CD — applying the project's own advice to itself)
- **Pinned the CI toolchain.** `ruff`, `mypy`, `pytest`, and `pytest-cov` were installed unpinned, so a
  third-party release could break the build with no change on our side — precisely the reproducibility
  gap Manifest's own B1 finding reports on other people's projects. Extras are installed without a
  silent `|| fallback`, since a degraded install turns real failures into skipped tests.
- **Enforced release ordering.** `bulwark-core` now publishes in its own job with the tools gated on
  `needs: core`. The matrix previously ran in parallel with a comment claiming core went first, which
  could leave PyPI briefly holding an `airlock` depending on a `bulwark-core` that did not exist.
- **Signed release artifacts** with Sigstore, using the same keyless OIDC identity Trusted Publishing
  already establishes. A project arguing for model signing should not ship unsigned wheels.
- **Bulwark now publishes its own AI-BOM** (CycloneDX, SPDX, and a governance report) as a release
  artifact.

### Fixed
- Benchmark harness no longer copies scan artifacts into the corpus directory (an earlier version
  silently inflated repeated runs); it now scans each file in place.

## [0.1.0] — Airlock · Warden · Manifest · bulwark-core

### Added
- **`bulwark-core`** — shared spine: `Finding`/`Severity`/`ScanResult`, YAML rule engine, signal IR,
  report renderers (terminal / JSON / HTML / SARIF), optional AI provider layer, resource limits.
- **Airlock** — static scanner for models (M1–M7), MCP servers (P1–P9), and tool-specs; formats:
  pickle, safetensors, GGUF, ONNX, Keras, numpy, TensorFlow SavedModel, Flax, PMML; hardened parsers;
  SARIF/CI; optional AI enrichment; corpus study harness; GitHub Action.
- **Warden** — least-privilege auditor: AgentSpec IR, capability graph, toxic-combination detection
  (A1–A10), agency score, framework importers (manifest / MCP config / OpenAI Assistants / LangChain /
  CrewAI), least-privilege recommendation, and `--scan-parts` (runs Airlock on wired MCP servers).
- **Manifest** — AI-BOM generator: discoverers, provenance/license resolution, OSV vulns, CycloneDX 1.5
  output, Airlock/Warden risk bridges (B1–B9), NIST AI RMF governance mapping.

[Unreleased]: https://github.com/mk12002/Bulwark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mk12002/Bulwark/releases/tag/v0.1.0
