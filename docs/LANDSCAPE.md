# Competitive & Research Landscape

Where Bulwark sits among existing tools, platforms, and academic work in AI supply-chain and agent
security (surveyed July 2026). Organized by the three layers Bulwark covers — **parts** (Airlock),
**assembly** (Warden), **system** (Manifest) — plus commercial platforms and research.

> TL;DR: The individual layers each have prior art (model scanners are mature; MCP scanners are
> emerging; AI-BOM generators exist). The **agent least-privilege** layer is largely research-only in
> the open-source world, and **no single open tool spans all three layers with one engine** — that
> composition is Bulwark's distinct position.

---

## 1. Model / pickle scanning (Airlock's model scanner)

This is the most mature space — and the one Airlock overlaps most directly.

| Tool | By | Notes |
| --- | --- | --- |
| **picklescan** | open source | Fast, HF-Hub-integrated; disassembles pickles, flags dangerous globals. The de-facto baseline. |
| **ModelScan** | Protect AI (now Palo Alto) | Open source; covers Pickle, PyTorch, Keras (H5 + v3), TF SavedModel, NumPy, Joblib. |
| **Guardian** | Protect AI | Commercial; "widest/deepest set of model scanners" — deserialization, architectural backdoors, runtime threats; native HF integration. |
| **Fickling** | Trail of Bits | Decompiles pickle streams to readable Python; in **Sept 2025** added an **allowlist-based** scanner (allow known-safe imports, block the rest) — the inverse of denylist detection. |
| **JFrog model scanner** | JFrog | Proprietary; one of the three scanners HF runs on every upload. |

**How the ecosystem actually works:** Hugging Face runs **picklescan + ModelScan + JFrog** on every
uploaded file; Protect AI's Guardian is also integrated. As of April 2025, Protect AI had scanned
**4.47M model versions across 1.41M repos and flagged ~352K unsafe/suspicious issues across ~51.7K
models**. Roughly **45% of popular HF models still use pickle** (CCS 2025).

**The 2025 evasion wave — directly relevant to Airlock's design.** Multiple critical bypasses of
picklescan were disclosed in 2025: a **file-extension bypass** (CVE-2025-10155, CVSS 9.3 — renaming a
malicious pickle to `.bin`/`.pt` made picklescan misclassify and skip it), three zero-days fixed in
**0.0.31** (Sept 2025), and four more found by Sonatype (Dec 2025). Cisco published **structure-aware
fuzzing** to harden pickle scanners. These are exactly the obfuscation classes Airlock's
**adversarial suite** targets (compression, extension/format confusion, base64 staging) and where the
**picklescan benchmark** shows Airlock catching evasive payloads picklescan misses — see
[`EMPIRICAL_VALIDATION.md`](EMPIRICAL_VALIDATION.md).

**Research:** *PickleBall* (arXiv 2508.15987) — secure deserialization by synthesizing per-model safe
loaders; *SafePickle* (arXiv 2602.19818) — ML-based malicious-pickle detection.

**Where Airlock fits:** open-source, same formats as ModelScan **plus** GGUF/Flax/PMML and
base64-nested/compressed handling; a benign, reproducible **adversarial + benchmark** methodology that
runs Airlock head-to-head against **picklescan, modelscan, and fickling** (Airlock is the only one to
catch all 14 evasive payloads; all four post zero false positives on benign models); and — unlike all of
the above — it is *one target type of three in a composable suite*. It does **not** claim Guardian's
scale/battle-testing or runtime protection.

Two Airlock detectors are drawn directly from the 2025 findings above:
- **Format/extension-confusion (M6)** — sniffs magic bytes and flags a pickle disguised under a safe
  extension, closing the CVE-2025-10155 bypass class *and* scanning the hidden pickle anyway.
- **Allowlist mode (`--strict`, M3)** — Fickling-style: flags pickle imports from modules *outside* the
  ML allowlist, catching novel callables a denylist misses (zero false positives on the 19-model
  corpus, whose weights import only from `torch`/`collections`).

---

## 2. MCP server scanning (Airlock's MCP scanner)

Newer and fast-moving; the MCP threat model crystallized in 2025.

| Tool / effort | By | Notes |
| --- | --- | --- |
| **MCP-Scan** | Invariant Labs | Connects to MCP servers; checks tool poisoning, cross-origin escalation, rug-pull, and **toxic-flow analysis**. The leading open tool. |
| **MCP-Scanner** | research (ACM 2026) | Multi-layer: keyword detection + semantic analysis + LLM evaluation for tool/variable poisoning, injection, rug-pull, impersonation. |
| **Snyk Labs guidance** | Snyk | Playbooks for detecting tool poisoning. |
| **cdxgen** | OWASP/AppThreat | Inventories MCP configs as part of AI-BOM (see §3). |

**Standards & benchmarks:** the **OWASP MCP Top 10 (2025)** codifies risks — **MCP03: Tool Poisoning**
is the headline. **MCPTox** (arXiv 2508.14925) is a tool-poisoning benchmark over ~45 real MCP servers.
A study of **1,899 open-source MCP servers found 7.2% had general vulnerabilities and 5.5% had
MCP-specific attack vectors** including tool poisoning. Threat-modeling papers: arXiv 2603.22489.

**Where Airlock fits:** static-first P1–P9 coverage (poisoning, hidden unicode, over-permissioning,
cross-tool exfil graph, secrets, rug-pull/TOFU, transport, shadowing) mapped to the OWASP MCP Top 10,
usable in CI with SARIF. Comparable in intent to MCP-Scan; Airlock's angle is the shared engine +
taxonomy with the rest of the suite and deterministic-first (no required LLM).

---

## 3. Agent least-privilege / excessive agency (Warden)

**This is the whitespace.** "Excessive Agency" is **OWASP LLM06:2025** and features in the **OWASP Top
10 for Agents (2026)** — named as a top risk, but tooling to *measure* it in a concrete agent assembly
is essentially research-only in the open-source world.

- **Named risk, few tools:** the guidance (remove unused tools, scoped credentials, approval gates,
  runaway guards) is well-documented, but there is no widely-adopted open tool that ingests an agent
  config and *scores* its over-privilege or finds toxic tool combinations.
- **Closest research:** *Auditing MCP Servers for Over-Privileged Tool Capabilities* (arXiv 2603.21641)
  — remarkably aligned with Warden's thesis, but a paper, not a shipped CLI. *Intent-Governed Tool
  Authorization for AI Agents* (arXiv 2606.22916) — a runtime authorization model (complementary:
  Warden is static/pre-deployment; intent-governance is runtime).
- **Commercial adjacency:** MLSecOps platforms (below) focus on model + runtime, not static
  least-privilege analysis of an agent's wiring.

**Where Warden fits:** a normalized **AgentSpec IR** across frameworks (manifest, MCP config, OpenAI
Assistants, LangChain/LangGraph, CrewAI), a **capability graph** that finds source→sink toxic
combinations, a transparent **agency score (0–100)**, **policy profiles**, and — the differentiator — a
**least-privilege recommendation** that rewrites an over-privileged agent. This is the most novel part
of the suite; there is little open-source competition.

---

## 4. AI-BOM / governance (Manifest)

An emerging, standards-driven space with regulatory tailwind (NIST AI RMF, EU AI Act).

| Tool | By | Notes |
| --- | --- | --- |
| **OWASP AIBOM Generator** | OWASP GenAI | Launched 2025; generates CycloneDX (SPDX-aligned) BOMs for **Hugging Face models**. |
| **cdxgen** | OWASP/AppThreat | Broad SBOM/BOM generator; AI-BOM for prompt files, AI services, **MCP configs**, model metadata, with governance/agentic findings. |
| **AIBoMGen** | research/CLI | Go CLI; scans repos for HF model usage, generates + validates + enriches + merges AI-BOMs with SBOMs. |

**Standards:** CycloneDX added **ML-BOM in v1.5 (2023)**; current spec is **v1.7 (Oct 2025,
ECMA-424)** with Data Provenance/Citations. An **Agent BOM** extension is under proposal (CycloneDX
spec issue #895). SPDX has AI/dataset profiles.

**Where Manifest fits:** it produces **both CycloneDX and SPDX**, discovers a broader component set
(models, datasets, MCP, prompts, tools, deps, **notebooks**), and — the differentiator — attaches
**integrated risk by calling Airlock and Warden** and maps to **NIST AI RMF *and* EU AI Act** with a
risk register and BOM diff. Most generators inventory + license; few fold in dedicated-scanner risk.

---

## 5. Commercial MLSecOps platforms (the enterprise tier)

| Platform | Focus |
| --- | --- |
| **Protect AI** (Palo Alto) | The most-cited MLSecOps stack: ModelScan, **Guardian** (model scanning), NB Defense, Recon (red teaming). |
| **HiddenLayer AISec** | Model integrity across MLOps; runtime detection of prompt injection, adversarial + supply-chain attacks. |
| **Robust Intelligence** (Cisco AI Defense) | Runtime AI firewall + red teaming + model validation. |
| **Cranium AI** | AI security posture / governance. |
| **Lakera** | Runtime prompt-injection / guardrails. |

These are proprietary, enterprise, and strongest at **model scanning + runtime protection**. None (as
of this survey) ship an open, static **agent least-privilege** analyzer or an open AI-BOM that composes
part-level and assembly-level scanners into one governable artifact.

---

## 6. Summary — Bulwark's position

| Layer | Prior art | Bulwark's role |
| --- | --- | --- |
| Parts — models | Mature (picklescan, ModelScan, Guardian, Fickling) | Airlock: open, broad formats, adversarial-tested vs the 2025 evasion CVEs |
| Parts — MCP | Emerging (MCP-Scan, MCP-Scanner) | Airlock: static-first P1–P9 on the OWASP MCP Top 10 |
| Assembly — agents | **Research-only** (arXiv 2603.21641, intent-governance) | **Warden: the novel piece** — capability graph, agency score, least-privilege rewrite |
| System — AI-BOM | Emerging (OWASP AIBOM Gen, cdxgen) | Manifest: CycloneDX+SPDX **with integrated Airlock/Warden risk** + dual governance |
| **Composition** | **None open-source spans all three** | **The suite: one engine, one taxonomy, parts→assembly→system** |

**The honest framing:** Bulwark does not out-scale Protect AI/HiddenLayer on model scanning or runtime
defense, and its individual scanners overlap existing open tools. Its distinct contributions are
(1) the **agent least-privilege analyzer** (rare in open source), (2) an **AI-BOM that folds in
dedicated-scanner risk** and maps to both NIST AI RMF and the EU AI Act, and (3) the **end-to-end
composition** under a shared engine — audited, reproducible, and CI-native.

---

## Sources

Model/pickle scanning: [Promptfoo ModelAudit](https://www.promptfoo.dev/blog/open-sourcing-modelaudit/) ·
[ModelScan (Protect AI)](https://github.com/protectai/modelscan) ·
[Fickling's new scanner (Trail of Bits)](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/) ·
[JFrog: PickleScan zero-days](https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/) ·
[Sonatype: 4 PickleScan vulns](https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities) ·
[The Hacker News: PickleScan bypass](https://thehackernews.com/2025/12/picklescan-bugs-allow-malicious-pytorch.html) ·
[Cisco: hardening pickle scanners](https://blogs.cisco.com/ai/hardening-pickle-file-scanners) ·
[PickleBall (arXiv)](https://arxiv.org/pdf/2508.15987) · [SafePickle (arXiv)](https://arxiv.org/html/2602.19818v1)

MCP scanning: [MCP-Scanner (ACM)](https://dl.acm.org/doi/10.1145/3786160.3788471) ·
[Snyk Labs: tool poisoning](https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/) ·
[OWASP MCP Top 10 — MCP03](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning) ·
[MCPTox (arXiv)](https://arxiv.org/pdf/2508.14925) ·
[Auditing over-privileged MCP tools (arXiv)](https://arxiv.org/html/2603.21641v1) ·
[MCP threat modeling (arXiv)](https://arxiv.org/html/2603.22489v1)

AI-BOM: [OWASP AIBOM Generator](https://genai.owasp.org/resource/owasp-aibom-generator/) ·
[cdxgen](https://github.com/cdxgen/cdxgen) · [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) ·
[Agent BOM proposal](https://github.com/CycloneDX/specification/issues/895) ·
[AIBoMGen (arXiv)](https://arxiv.org/pdf/2601.05703)

Excessive agency: [OWASP LLM06:2025](https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/) ·
[OWASP Top 10 for Agents 2026](https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications) ·
[Intent-governed tool authorization (arXiv)](https://arxiv.org/pdf/2606.22916)

Platforms: [Protect AI Guardian](https://protectai.com/guardian) · [HiddenLayer](https://www.hiddenlayer.com/platform) ·
[Top MLSecOps platforms 2026](https://guptadeepak.com/tools/top-5-mlsecops-platforms-2026/) ·
[HF × Protect AI: 4M models scanned](https://huggingface.co/blog/pai-6-month) ·
[HF security scanners](https://huggingface.co/docs/hub/en/security-protectai)
