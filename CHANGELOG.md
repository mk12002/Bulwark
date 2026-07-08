# Changelog

All notable changes to Bulwark are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
