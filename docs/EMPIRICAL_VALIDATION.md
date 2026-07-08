# Empirical validation

Bulwark is validated three ways, all reproducible from the repo: a **corpus study** over real
public models, an **adversarial robustness suite** of evasive-but-benign payloads, and a
head-to-head **benchmark against picklescan**. This document summarizes the results and how to
regenerate them.

> The model corpus lives under `datasets/` (gitignored, ~324 MB). Rebuild it with
> `python packages/airlock/scripts/build_corpus.py`. The generated result tables are committed at
> [`packages/airlock/docs/CORPUS_STUDY.md`](../packages/airlock/docs/CORPUS_STUDY.md) and
> [`packages/airlock/docs/BENCHMARK.md`](../packages/airlock/docs/BENCHMARK.md). For the complete
> dataset inventory, provenance, and per-test methodology, see
> [`DATASETS_AND_TESTING.md`](DATASETS_AND_TESTING.md).

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

## 3. Benchmark vs. picklescan

Both tools were asked the same question on every pickle artifact — *do you flag code execution?*

| Group | Airlock | picklescan |
| --- | :---: | :---: |
| **Adversarial** (14 evasive payloads) | **14/14** | 10/14 |
| **Real models** (18 benign `.bin`) | 0/18 | 0/18 |

Three takeaways:

- **On evasive payloads Airlock catches more** than picklescan — the **gzip/zlib-compressed** and
  **base64-staged** variants (and it handles the `.npy` object array picklescan's file-path entry
  skips) — because it decompresses and decodes one level before disassembling.
- **On the format-spoofing file both flag code execution** (a current picklescan sniffs content), but
  only Airlock emits the explicit **M6 format-mismatch** finding that names the deception.
- **On real benign models both agree: no code-execution false alarms.** Airlock still reports the
  pickle *surface* risk (M2) and the missing-safetensors/provenance advisories (M4/M7) — a risk
  posture, not a cry of "malware" — which is the correct, non-noisy behavior.

Reproduce with `python packages/airlock/scripts/benchmark.py datasets/corpus.txt`.

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

## Honesty notes

- These are *tiny reference* models, chosen so the corpus is small and downloadable; the prevalence
  numbers describe distribution/provenance hygiene, not that these specific models are malicious (they
  are benign — hence 0/18 on code execution).
- picklescan is a focused, well-regarded pickle scanner; the comparison is scoped to pickle
  code-execution detection, which is one of Airlock's checks among many (MCP, tool-specs, ONNX/Keras/TF
  formats, provenance) that picklescan does not attempt.
