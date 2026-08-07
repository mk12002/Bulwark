# Taxonomy

**35 categories** across four families, **42 shipped rules**. Every finding maps to
exactly one category, and every category cites an external standard.

`airlock rules list` prints every detection the tool performs — auditability is a
product feature, not an afterthought.

## Airlock — model risks (M1–M7)

| Code | Title | Default | References |
|---|---|---|---|
| **M1** | Arbitrary code execution via pickle deserialization | CRITICAL | `OWASP:LLM03:2025`, `CWE-502` |
| **M2** | Unsafe deserialization surface | HIGH | `CWE-502` |
| **M3** | Suspicious payload signatures | HIGH | `OWASP:LLM03:2025` |
| **M4** | Risky serialization format | MEDIUM | safetensors guidance |
| **M5** | Remote/custom code execution via config | HIGH | `OWASP:LLM03:2025`, `CWE-494` |
| **M6** | Archive smuggling and format confusion | HIGH | `CWE-22`, `CWE-506`, `CWE-646` |
| **M7** | Provenance and integrity gaps | LOW | `OWASP:LLM03:2025`, `SLSA` |

The **M1/M2 split** is the most important calibration in the tool: M2 fires on 89% of
real models (a `REDUCE` opcode exists), M1 on 0% of benign ones (a *dangerous callable*
is referenced). One combined category would make the scanner either useless or ignored.

## Airlock — MCP and tool-spec risks (P1–P9)

| Code | Title | Default | References |
|---|---|---|---|
| **P1** | Tool poisoning | HIGH | `OWASP:LLM01:2025`, `MITRE-ATLAS` |
| **P2** | Injection via tool output | HIGH | `OWASP:LLM01:2025` |
| **P3** | Hidden / obfuscated content | HIGH | `CWE-176`, `OWASP:LLM01:2025` |
| **P4** | Over-permissioned tools | HIGH | `OWASP:LLM06:2025`, `CWE-269` |
| **P5** | Confused deputy / cross-tool exfiltration | HIGH | `OWASP:LLM06:2025`, `OWASP:LLM02:2025` |
| **P6** | Secret / credential leakage | HIGH | `OWASP:LLM02:2025`, `CWE-798` |
| **P7** | Rug-pull / TOFU | MEDIUM | `CWE-494` |
| **P8** | Insecure transport / weak auth | MEDIUM | `CWE-319`, `CWE-306` |
| **P9** | Tool shadowing / name collision | MEDIUM | `CWE-706` |

**P3 is the strongest of these.** Zero-width characters, Unicode tag characters, bidi
overrides and homoglyphs have no legitimate purpose in a tool name, so it is close to a
bright-line rule rather than a heuristic — and it holds against novel phrasings that
defeat every phrase regex.

## Warden — excessive agency (A1–A10)

| Code | Title | Default | References |
|---|---|---|---|
| **A1** | Excessive tool scope | MEDIUM | `OWASP:LLM06:2025`, `CWE-269` |
| **A2** | Dangerous tool combination | HIGH | `OWASP:LLM06:2025`, `OWASP:LLM02:2025` |
| **A3** | Missing human-in-the-loop | HIGH | `OWASP:LLM06:2025` |
| **A4** | Over-broad system-prompt authority | MEDIUM | `OWASP:LLM01:2025` |
| **A5** | Unrestricted egress | HIGH | `OWASP:LLM02:2025` |
| **A6** | Secrets in the assembly | HIGH | `CWE-798` |
| **A7** | Excessive data/memory access | MEDIUM | `OWASP:LLM06:2025` |
| **A8** | Unsandboxed code/shell execution | HIGH | `CWE-250` |
| **A9** | Untrusted/unscanned parts wired in | MEDIUM | `OWASP:LLM03:2025` |
| **A10** | No runaway guards | MEDIUM | `OWASP:LLM06:2025` |

**A2 escalates.** A source and a sink coexisting is HIGH — the chain is *possible*. Add
an untrusted-input capability such as browsing or inbound messages and it becomes
**CRITICAL**: an attacker can now *trigger* it. That is the lethal trifecta, implemented
as a set intersection rather than described as a concept.

Six of the ten checks are **structural** — they depend on declared configuration facts
rather than text heuristics, so they cannot be evaded by rewording a tool description.

## Manifest — governance (B1–B9)

| Code | Title | Default | References |
|---|---|---|---|
| **B1** | Undeclared / unpinned component | MEDIUM | `SLSA` |
| **B2** | Missing provenance | MEDIUM | `NIST-AI-RMF`, `SLSA` |
| **B3** | License risk | MEDIUM | SPDX licence list |
| **B4** | Known-vulnerable dependency | *from advisory* | `OSV` |
| **B5** | High-risk component (from Airlock/Warden) | *inherited* | `OWASP:LLM03:2025` |
| **B6** | Dataset governance gap | MEDIUM | `NIST-AI-RMF` |
| **B7** | Secret / credential exposure | HIGH | `CWE-798` |
| **B8** | Unversioned prompt template | LOW | change-management practice |
| **B9** | Compliance control gap | LOW | `NIST-AI-RMF` |

**B4 and B5 inherit severity** rather than using a fixed default, which is what makes
`--fail-on` transitive through the composition: a CRITICAL M1 on a model produces a
CRITICAL B5 on the owning component, so `bulwark scan --fail-on critical` fails.

## Severity model

| Severity | SARIF level | `security-severity` | Gates by default? |
|---|---|---|---|
| CRITICAL | `error` | 9.5 | yes |
| HIGH | `error` | 8.0 | **yes** — `--fail-on high` is the default |
| MEDIUM | `warning` | 5.0 | no |
| LOW | `note` | 2.0 | no |
| INFO | `note` | 0.0 | no |

**Severity and confidence are separate axes.** Severity is *how bad if real*;
confidence is *how sure the detector is*. Collapsing them produces either noise (a
heuristic marked CRITICAL) or buried findings (a real issue marked LOW). Warden's
policy profiles filter on both.

## Governance mapping

| NIST AI RMF function | Categories |
|---|---|
| GOVERN | B3, B9 |
| MAP | B1, B2, B6, B8 |
| MEASURE | B4, B5, B7, all M-codes, all P-codes, most A-codes |
| MANAGE | **A3, A10** |

A3 and A10 landing in MANAGE rather than MEASURE is deliberate: missing gates and
missing limits are *response* gaps, not measurement gaps.

| EU AI Act article | Categories |
|---|---|
| Art.10 Data governance | B6, B1, B2 |
| Art.11 Technical documentation | B1, B2, B8 |
| Art.12 Record-keeping | B8, B9 |
| Art.13 Transparency | B3 |
| Art.14 Human oversight | **A3, A10, A4** |
| Art.15 Accuracy, robustness and cybersecurity | B4, B5, B7, M-codes, P-codes, A2, A5, A8 |

Article 15 names resilience against third parties exploiting vulnerabilities, and names
data and model poisoning explicitly — which is Airlock's and Warden's threat model in
regulatory language. Article 14 mapping to Warden's A3 turns "human oversight" from a
process requirement into a technical measurement.

!!! warning "Advisory, not compliance"
    The mapping identifies **evidence gaps** against named controls. It does not
    determine compliance — that depends on your risk tier, your role in the value chain
    as provider or deployer, and your use case, none of which a scanner can know.
