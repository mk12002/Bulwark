# Empirical validation

Bulwark's thesis is that risk lives at three levels — the **parts**, the **assembly**, and
the **whole system** — so validation has to happen at all three. Each layer asks a
different question and therefore needs a different kind of evidence:

| Layer | Tool | The claim under test | Harness |
| --- | --- | --- | --- |
| Parts | 🔒 Airlock | detection survives obfuscation of a file, without crying wolf | `packages/airlock/scripts/` |
| Assembly | ⚖️ Warden | composition is recovered regardless of framework, and reported precisely | `packages/warden/scripts/study.py` |
| System | 📋 Manifest | the inventory is complete, conformant, governable, and composes | `packages/manifest/scripts/study.py` |

Everything below is reproducible from this repo. Per-tool detail lives in
[`packages/warden/docs/VALIDATION.md`](../packages/warden/docs/VALIDATION.md) and
[`packages/manifest/docs/VALIDATION.md`](../packages/manifest/docs/VALIDATION.md).

> The model corpus lives under `datasets/` (gitignored, ~324 MB). Rebuild it with
> `python packages/airlock/scripts/build_corpus.py`. The generated result tables are committed at
> [`packages/airlock/docs/CORPUS_STUDY.md`](../packages/airlock/docs/CORPUS_STUDY.md),
> [`packages/airlock/docs/BENCHMARK.md`](../packages/airlock/docs/BENCHMARK.md),
> [`packages/warden/docs/VALIDATION_DATA.md`](../packages/warden/docs/VALIDATION_DATA.md), and
> [`packages/manifest/docs/VALIDATION_DATA.md`](../packages/manifest/docs/VALIDATION_DATA.md).
> For the complete dataset inventory, provenance, and per-test methodology, see
> [`DATASETS_AND_TESTING.md`](DATASETS_AND_TESTING.md).

---

# The part layer — Airlock

## 1. Corpus study — real public models

`airlock study` was run over **19 public HuggingFace models** (tiny/test models spanning GPT-2, BERT,
DistilBERT, RoBERTa, T5, BART, Albert, MobileBERT, Electra, Deberta, Llama, Mistral, GPT-NeoX, OPT,
Bloom, CLIP), a real mix of serialization formats — **18 pickle `.bin`, 14 Keras `.h5`, 15 ONNX,
4 safetensors**.

| Metric | Result |
| --- | --- |
| Models scanned | 19 (0 errored) |
| **Prevalence** (≥1 finding) | **100%** |
| Ship pickle-serialized weights | 18/19 (95%) |
| Contain a `REDUCE` opcode (exec surface) | 17/19 (89%) |
| Ship pickle **without** a safetensors alternative | 14/19 (74%) |
| No published hashes to verify integrity | 19/19 (100%) |
| No model card | 16/19 (84%) |

The headline: *pickle-based distribution is still overwhelmingly the norm even among reference models,
and provenance/integrity metadata is almost always absent* — precisely the supply-chain surface Airlock
exists to make visible. Reproduce with `airlock study datasets/corpus.txt --format markdown`.

## 2. Adversarial robustness — does static analysis survive obfuscation?

`scripts/adversarial.py` generates **14 evasive-but-benign** pickle artifacts (each references
`os.system` but only `echo`s an inert marker; nothing is ever unpickled). They probe whether the
scanner can be evaded by:

- pickle **protocols 0–5** and **framed** pickles,
- **`STACK_GLOBAL`** instead of the classic `GLOBAL` opcode (no `c os\nsystem` substring in the file),
- **gzip/zlib-compressed** pickles wearing a `.bin` model extension,
- a **base64-staged** nested pickle,
- an object-dtype **`.npy`** hiding a pickle,
- a **torch-style zip** (pickle as an inner archive member),
- **format spoofing** — a pickle renamed `model.safetensors` to dodge an extension-based classifier
  (the picklescan **CVE-2025-10155** bypass class).

**Result: Airlock flags code execution (M1) on 14/14**, and additionally raises a dedicated
format-spoofing finding (**M6**) on the disguised file. Locked in by
[`tests/test_adversarial.py`](../packages/airlock/tests/test_adversarial.py), which fails if any
obfuscation slips a payload past the scanner.

## 3. Benchmark vs. picklescan, modelscan, and fickling

Every scanner is asked the same question on every pickle artifact — *do you flag code execution?*
(`n/a` = the tool cannot process that input, e.g. fickling does not handle zip/gzip-wrapped pickles.)

| Group | Airlock | picklescan | modelscan | fickling |
| --- | :---: | :---: | :---: | :---: |
| **Adversarial** (14 evasive payloads) | **14/14** | 11/14 | 9/14 | 9/14 |
| **Real models** (18 benign `.bin`) | **0/18** | 0/18 | 0/18 | 0/18 |

Three takeaways:

- **Airlock is the only scanner that catches all 14 evasions.** Its edge is the **gzip/zlib-compressed**
  and **base64-staged** variants — it decompresses and decodes one level before disassembling — which
  every other tool misses.
- **On the format-spoofing file, current picklescan sniffs content and catches it too**, but only
  Airlock emits the explicit **M6 format-mismatch** finding that names the deception.
- **On real benign models all four agree: 0/18 code-execution false alarms.** This true-negative parity
  is the number that matters most — catching attacks is easy if you cry wolf; not flagging 18 legit
  models as malware is the hard part. (Airlock still reports the pickle *surface* risk M2 and the
  provenance advisories M4/M7 — a risk posture, not a false alarm.)

Reproduce with `pip install picklescan modelscan fickling` then
`python packages/airlock/scripts/benchmark.py datasets/corpus.txt`. Missing competitors are simply
omitted, so it runs with whatever is installed.

## 4. Research-driven detectors

Two Airlock detectors are directly informed by the 2025 threat landscape (see
[`LANDSCAPE.md`](LANDSCAPE.md)):

- **Format/extension-confusion (M6)** — sniffs magic bytes and flags any file whose bytes are a pickle
  but whose extension claims a safe format, defeating the extension-rename bypass class
  (CVE-2025-10155) *and* scanning the hidden pickle so a dangerous payload still trips M1/M2.
- **Allowlist mode (M3, opt-in `--strict`)** — Fickling-style: instead of only blocking known-dangerous
  imports, it surfaces any pickle import from a module *outside* the ML allowlist (torch/numpy/…),
  catching novel callables a denylist has never seen. Verified to produce **zero false positives** on
  the 19-model corpus (real weights import only from `torch`/`collections`).

---

# The assembly layer — Warden

Reproduce all four with `python packages/warden/scripts/study.py`. Full discussion:
[`packages/warden/docs/VALIDATION.md`](../packages/warden/docs/VALIDATION.md).

## 5. Cross-framework invariance

Warden claims the analysis engine never has to know which framework you use. The **same logical
agent** — browse the web, read a secret, POST to a URL — was written in four framework encodings
and audited.

| Importer | Capabilities recovered | A-codes | A2 fires |
| --- | --- | --- | :---: |
| `manifest` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |
| `openai_assistant` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |
| `crewai` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |
| `langchain` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |

**Result: 4/4 encodings produce an identical capability set and an identical A-code set.** The IR
abstraction holds. `mcp_config` is excluded rather than scored: an `.mcp.json` names *servers*, not
tools, so it cannot express a tool-level assembly at all.

## 6. Lexicon robustness — where Warden stops

A2 depends on classifying tools via a keyword lexicon. The same kill chain was expressed with
progressively less lexical signal:

| Variant | Capabilities recovered | A2 fires |
| --- | --- | :---: |
| `explicit` — names and descriptions both state it | browse, net_out, secret_read | **yes** |
| `snake_case_only` — names only, no descriptions | browse, net_out, secret_read | **yes** |
| `camelCase_only` — camelCase names, no descriptions | browse, net_out, secret_read | **yes** |
| `opaque_names_rich_desc` — capability only in prose | net_out, secret_read | **yes** |
| `paraphrased` — unlisted synonyms | *none* | no |
| `scope_only` — capability only in scope strings | secret_read | no |
| `opaque_no_signal` — no signal at all (the floor) | *none* | no |

**Result: A2 recovered on 4/7 variants.** This bounds the claim honestly, and the misses are not all
the same kind:

- **`camelCase_only` was a defect this study found, and it is now fixed.** `_tool_text()` de-snaked
  `_`/`-` so `\bbrowse\b` matched `browse_web`, but did not split case transitions — so `browseWeb`
  was unclassifiable and **every camelCase assembly silently lost A2** while still reporting a
  clean-looking MEDIUM verdict. That covers most of the TypeScript MCP ecosystem. snake_case and
  camelCase now classify identically, pinned by a regression test.
- **`paraphrased` and `opaque_no_signal` are the ceiling of keyword matching**, not a tuning problem.
  This is the argument for the optional AI layer and for reading capability from MCP tool *schemas*
  rather than prose.

Warden is reliable when tool names or descriptions are conventional and degrades to silence when they
are not — it does not emit a misleadingly clean verdict, but the compositional finding is absent.

## 7. False positives on benign assemblies

Seven harmless agents built around vocabulary the lexicon watches for (`format_response`, "open a
support ticket", "query the user", "transfer the meaning").

**Result: 0/7 spurious A2, and 3/7 carry a HIGH+ finding** — down from 5/7, because this study found
two more lexicon defects and both are fixed:

- **`transfer`/`wire` → FINANCIAL** now require a money noun. "Transfer the meaning of a phrase" was
  classified as a financial operation, and since FINANCIAL is HIGH_IMPACT it also produced a spurious
  A3 missing-gate finding on a translation tool. ("Transfer learning" would have tripped it too.)
- **`request` → NET_OUT** now requires network context. A bare `\brequest\b` matched "the user's
  request" — ordinary English long before it is an HTTP verb.

Three residual taggings remain and are judgement calls rather than bugs: `delete_draft` really is a
delete, `update_status` really is a write, and "runs in a sandboxed viewer" is at least adjacent to
execution. Narrowing those would cost true positives. **The compositional layer is precise; the
capability layer under it is deliberately cautious.**

## 8. Recommendation efficacy

Each fixture audited, passed through `recommend()`, then re-audited.

**Result: across the six specs with something to harden, mean agency score falls 52.5 → 31.2 (−21.3)
and HIGH+ findings fall 17 → 8.** The minimal `clean.yaml` control is left untouched (0 changes),
which is the property that matters most.

Residual A2 is deliberate: Warden adds gates, sandboxes, scope allow-lists, and runaway guards
because those preserve intent, but it will not delete a tool to break a toxic combination — that
changes what the agent is for, so it emits an advisory and leaves the call to a human.

---

# The system layer — Manifest

Reproduce all four with `python packages/manifest/scripts/study.py`. Full discussion:
[`packages/manifest/docs/VALIDATION.md`](../packages/manifest/docs/VALIDATION.md).

## 9. Discovery recall vs. hand-written ground truth

Ground truth written by hand from the fixture trees, not from Manifest's own output.

| Project | Expected | Found | Recall |
| --- | :---: | :---: | :---: |
| `sample_project_clean` | 4 | 4 | 100% |
| `sample_project_risky` | 11 | 11 | 100% |

**Result: 15/15 components discovered, no unexplained extras.** The substantive part is *where* they
came from: only 3 of the risky project's 11 components are in `requirements.txt`. The rest are
embedded — `torch` and `datasets` from a notebook `!pip install` line, `google/flan-t5-small` from a
`from_pretrained()` call, `imdb` from `load_dataset()`, and a prompt from `agent.yaml`. A dependency
scanner reading only `requirements.txt` would report 3 of 11 and call the project inventoried.

## 10. BOM conformance

**Result: 10/10 conformance checks pass** across CycloneDX and SPDX — required document fields,
format identifiers, `urn:uuid` and `SPDXRef-` identifier forms, per-component required fields, valid
CycloneDX component-type enum values, and dependency refs that resolve.

This is a **required-field and well-formedness check against the specs' documented rules, not full
JSON-Schema validation** against the upstream schema documents (which would make CI
network-dependent). "Structurally conformant" is the accurate claim; schema validation against
vendored schemas is worthwhile and not yet done.

## 11. Governance coverage

| Framework | Controls | Exercised | Breakdown |
| --- | :---: | :---: | --- |
| NIST AI RMF | 4 | 3 | GOVERN (8), MAP (7), MEASURE (2), MANAGE (0) |
| EU AI Act | 6 | 5 | Art.10 (6), Art.11 (6), Art.12 (4), Art.13 (5), Art.15 (2), Art.14 (0) |

Every B-code the project produced (B1, B3, B4, B6, B7, B8, B9) maps to at least one control — no
finding is orphaned from the governance view.

**The two zeros are structural, not accidental.** NIST `MANAGE` and EU `Art.14 Human oversight` are
about organizational process — who reviews, who signs off, what happens when risk is accepted. A
static scan has nothing to say about either. They are mapped so the gap is *visible* in the report
rather than silently absent.

## 12. Risk-bridge fidelity

`--scan-risk` runs Airlock and Warden on discovered components and folds findings in as B5. The two
failure modes — silent drop and double-counting — are measured directly.

**Result: 6/6 checks pass.** Baseline 14 findings across 6 codes → bridged 21 across 10 codes;
every baseline code survives, and 0 of 21 `(rule, location)` pairs are duplicated. Bridging is purely
additive. (A finding `id` legitimately repeats across components — `B1-unpinned` fires once per
unpinned dependency — so uniqueness is measured on the `(rule, location)` instance key.)

---

## Honesty notes

**Airlock**

- These are *tiny reference* models, chosen so the corpus is small and downloadable; the prevalence
  numbers describe distribution/provenance hygiene, not that these specific models are malicious (they
  are benign — hence 0/18 on code execution).
- picklescan is a focused, well-regarded pickle scanner; the comparison is scoped to pickle
  code-execution detection, which is one of Airlock's checks among many (MCP, tool-specs, ONNX/Keras/TF
  formats, provenance) that picklescan does not attempt.

**Warden**

- All three composition studies are built around one kill chain (browse → secret_read → net_out). It
  is the canonical case A2 was designed for; other toxic pairs are not yet measured.
- The fixtures are authored by this project. The 0/7 false-positive result says the lexicon survives
  seven traps chosen by someone who knew where the traps were — it does not estimate a false-positive
  rate on real configs.

**Manifest**

- **n = 2 projects**, both authored here. 100% recall is a regression guarantee on two small trees,
  not an estimate of recall on real repositories.
- Recall only — because nothing unexpected was reported, there is no precision measurement at all.
- Studies run `offline=True`, so OSV vulnerability and license resolution do not run and the
  B-codes depending on them are underrepresented.

**Suite-wide**

The single largest gap across all three layers is the same one: **every corpus except Airlock's
19-model study is authored by this project.** These studies bound behaviour and lock it against
regression; they do not estimate population statistics. A corpus study over public agent
configurations and public ML repositories is the outstanding work that would change that.
