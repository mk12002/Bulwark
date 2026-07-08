# Security Policy

Bulwark is a defensive security tool that, by design, **ingests hostile input** (untrusted model
artifacts, MCP servers, and agent configs). We take its own security seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via one of:

- **GitHub Security Advisories** — the "Report a vulnerability" button under the repository's
  **Security** tab (preferred; keeps the report private and tracked).
- **Email** — the maintainer address listed on the GitHub profile, with `SECURITY` in the subject.

Please include:

- The affected package (`bulwark-core`, `airlock`, `warden`, `manifest`, or `bulwark`) and version.
- A description of the issue and its impact.
- Reproduction steps or a proof-of-concept (a **benign** one — see below).
- Any suggested remediation.

We aim to acknowledge reports within **72 hours** and to provide a remediation timeline after triage.

## Scope

Security-relevant issues include, but are not limited to:

- A crafted artifact that causes Bulwark to **execute code**, escape its static-analysis boundary, or
  invoke `pickle.load` / `torch.load` / import target code (this must **never** happen — Bulwark is
  inspection-only).
- A resource-exhaustion vector (decompression bomb, opcode blow-up, path traversal on extraction) that
  bypasses the limits in `bulwark_core.limits`.
- A scanner **evasion** — an artifact that is genuinely malicious but which Bulwark reports as clean.
  Evasion reports are especially welcome; the adversarial suite exists precisely to catch these.

## Proof-of-concept guidelines

Bulwark is a **defensive, detection-oriented** project. When submitting a PoC:

- Keep payloads **benign and inert** — e.g. a pickle whose payload runs `echo <marker>` or writes a
  harmless sentinel, never anything destructive, network-exfiltrating, or self-propagating.
- Do not include real malware, real secrets, or live C2.
- Mirror the pattern in `packages/airlock/tests/test_adversarial.py`, which demonstrates code-execution
  detection without any harmful behavior.

## Supported versions

Bulwark is at `v0.1`. Security fixes are applied to the latest release. Once tagged releases exist on
PyPI, this table will track supported versions.

## Our commitments

- **Inspection only.** Bulwark never deserializes or executes what it scans; a regression here is a
  top-severity bug.
- **Deterministic-first.** The optional AI layer is off by default and never gates or downgrades a
  deterministic finding.
- **Benign fixtures only.** Every test artifact that simulates an attack uses inert markers.
