# External Datasets & Testing — Full Reference

Everything about the **external data** Bulwark is tested against and the **tests run on it**: where the
data comes from, how it's fetched, exact sizes and formats, every command, every result, how to
reproduce it, and the data-handling rules. This is the authoritative companion to the shorter
[`EMPIRICAL_VALIDATION.md`](EMPIRICAL_VALIDATION.md).

> **Why external data at all?** Fixtures prove a scanner works on inputs you designed. External data
> proves it works on inputs you *didn't* — real models off the Hub, and a real competitor's verdicts.
> That's the difference between "it passes my tests" and "it works."

---

## 1. Data-handling rules (read first)

- **Nothing external is committed.** The entire `datasets/` directory is **gitignored**. Models are
  downloaded on demand; results are regenerated. The repo stays small and reproducible.
- **Nothing is executed.** Every model file is inspected **statically** (byte/opcode level). No
  `pickle.load`, no `torch.load`, no importing repo code. Downloading a model and scanning it never runs
  it.
- **The adversarial data is benign.** The "malicious" payloads are generated locally and only reference
  `os.system("echo <marker>")` — an inert echo. Nothing is ever unpickled; even if a file were loaded by
  accident, it does nothing harmful.
- **No real secrets.** The sample config files use obvious placeholder tokens.

---

## 2. The `datasets/` layout

```
datasets/                         # gitignored in full
├── corpus/                       # Dataset 1: 19 real HuggingFace models (~324 MB)
│   ├── prajjwal1__bert-tiny/
│   ├── sshleifer__tiny-gpt2/
│   └── hf-internal-testing__tiny-random-*/   (17 more)
├── corpus.txt                    # study manifest: one "model <path>" per line
├── _benchmark_adv/               # Dataset 2: 14 generated evasive payloads (regenerated each run)
├── agent_manifest.yaml           # Dataset 3: sample agent config (Warden)
├── claude_desktop_config.json    # Dataset 3: sample MCP client config (Warden/Airlock)
├── openai_tools.json             # Dataset 3: sample tool-spec (Airlock)
├── tinygpt2_scan.json            # a saved scan result (sample output)
└── hf_err.txt                    # captured error output (notes)
```

Three distinct datasets serve three purposes. Each is documented below.

---

## 3. Dataset 1 — the real HuggingFace model corpus

**What:** 19 public, tiny "test/random" models spanning the major architectures. Tiny models are chosen
deliberately: they ship the *same real serialization formats* as production models (pickle, safetensors,
Keras H5, ONNX, Flax) but are a few MB each, so the corpus is downloadable and the study is fast.

**Provenance:** all public repos on the Hugging Face Hub — 17 under `hf-internal-testing/` (HF's own test
org), plus `prajjwal1/bert-tiny` and `sshleifer/tiny-gpt2`.

**Size:** ~324 MB across 19 repos.

### 3.1 The models

| # | Model repo | Size |
| --- | --- | --- |
| 1 | `prajjwal1/bert-tiny` | 68 MB |
| 2 | `sshleifer/tiny-gpt2` | 12 MB |
| 3 | `hf-internal-testing/tiny-random-gpt2` | 23 MB |
| 4 | `hf-internal-testing/tiny-random-GPT2LMHeadModel` | 7.6 MB |
| 5 | `hf-internal-testing/tiny-random-BertModel` | 2.5 MB |
| 6 | `hf-internal-testing/tiny-random-DistilBertModel` | 2.0 MB |
| 7 | `hf-internal-testing/tiny-random-RobertaModel` | 2.8 MB |
| 8 | `hf-internal-testing/tiny-random-MobileBertModel` | 17 MB |
| 9 | `hf-internal-testing/tiny-random-AlbertModel` | 79 MB |
| 10 | `hf-internal-testing/tiny-random-ElectraModel` | 5.1 MB |
| 11 | `hf-internal-testing/tiny-random-DebertaModel` | 1.9 MB |
| 12 | `hf-internal-testing/tiny-random-t5` | 11 MB |
| 13 | `hf-internal-testing/tiny-random-BartModel` | 1.6 MB |
| 14 | `hf-internal-testing/tiny-random-LlamaForCausalLM` | 14 MB |
| 15 | `hf-internal-testing/tiny-random-MistralForCausalLM` | 42 MB |
| 16 | `hf-internal-testing/tiny-random-GPTNeoXForCausalLM` | 7.6 MB |
| 17 | `hf-internal-testing/tiny-random-OPTForCausalLM` | 26 MB |
| 18 | `hf-internal-testing/tiny-random-BloomModel` | 1.7 MB |
| 19 | `hf-internal-testing/tiny-random-CLIPModel` | 4.5 MB |

A 20th candidate (`hf-internal-testing/tiny-random-XLMRobertaModel`) was in the list but 404'd at fetch
time; the downloader tolerates misses and records what actually landed, so the corpus is 19.

### 3.2 Format inventory (the point of this corpus)

Excluding the HuggingFace download cache, the corpus contains a real mix of serialization formats — which
is exactly why it's a good test bed for a multi-format scanner:

| Format | Files | What it exercises |
| --- | --- | --- |
| pickle `pytorch_model.bin` | **18** | M1/M2/M3 opcode disassembly, M4 advisory |
| Keras `tf_model.h5` | **14** | Keras Lambda-layer (M5) path |
| ONNX `model.onnx` | **15** | ONNX external-data / custom-op (M5/M6) path |
| safetensors | **4** | the safe-format true-negative path |
| Flax `flax_model.msgpack` | **1** | msgpack safe-format path |

### 3.3 How it's downloaded

Script: [`packages/airlock/scripts/build_corpus.py`](../packages/airlock/scripts/build_corpus.py).

```bash
python packages/airlock/scripts/build_corpus.py
```

It calls `huggingface_hub.snapshot_download` for each repo with an `allow_patterns` filter (only weight,
config, and code files — never gigabytes), writes each into `datasets/corpus/<sanitized-id>/`, tolerates
404s/network errors, and writes the `datasets/corpus.txt` manifest (`model <abs-path>` per line). No
authentication is needed (all repos are public).

---

## 4. Dataset 2 — the adversarial (evasive) corpus

**What:** 14 **benign-but-evasive** pickle artifacts, generated locally, that probe whether Airlock's
static analysis can be *bypassed*. Each references `os.system` the way a real attack would, but the only
argument is `echo airlock-benign-marker` — inert. Nothing is ever unpickled.

**Generator:** [`packages/airlock/scripts/adversarial.py`](../packages/airlock/scripts/adversarial.py)
(`build_adversarial_corpus`). It's shared by the test suite and the benchmark, so the package itself
ships no pickle-generation code in its importable modules.

### 4.1 The 14 variants

| Variant | Evasion technique it probes |
| --- | --- |
| `reduce_proto0` … `reduce_proto5` | pickle protocols 0–5 (baseline across the format's versions) |
| `stack_global` | `STACK_GLOBAL` instead of classic `GLOBAL` — no `c os\nsystem` substring in the file |
| `stack_global_framed` | protocol-5 framed pickle |
| `gzip_bin` | gzip-compressed pickle wearing a `.bin` extension |
| `zlib_bin` | zlib-compressed pickle wearing a `.bin` extension |
| `base64_nested` | a pickle whose string payload base64-decodes to another dangerous pickle (staged) |
| `npy_object` | an object-dtype `.npy` array hiding a pickle |
| `torch_zip` | torch-style zip with the pickle as an inner archive member |
| `disguised_safetensors` | a pickle renamed `model.safetensors` (the CVE-2025-10155 bypass class) |

### 4.2 Safety

Every payload is generated at test/benchmark time into a scratch directory, only ever
`echo`s a marker, and is only ever *disassembled*, never executed. This is the defensive-only principle
in practice.

---

## 5. Dataset 3 — real-world config samples

Small, realistic config files used to exercise Warden and Airlock's non-model scanners against
real-world shapes (with placeholder secrets):

| File | Used by | Purpose |
| --- | --- | --- |
| `claude_desktop_config.json` | Warden import / Airlock MCP | a real-shape MCP client config (which servers are wired) |
| `agent_manifest.yaml` | Warden audit | a realistic agent manifest (tools, scopes, prompt, autonomy) |
| `openai_tools.json` | Airlock toolspec | an OpenAI-style tool-definition file |
| `tinygpt2_scan.json` | reference | a saved `ScanResult` from a real `hf:sshleifer/tiny-gpt2` scan |

---

## 6. The three testing activities

### 6.1 Corpus study — prevalence over real models

**Method:** run every model in the manifest through Airlock's model scanner and aggregate.

```bash
airlock study datasets/corpus.txt --format markdown --out packages/airlock/docs/CORPUS_STUDY.md
```

**Results (19 models, 0 errored):**

| Metric | Result |
| --- | --- |
| **Prevalence** (≥1 finding) | **100%** (19/19) |
| Ship pickle-serialized weights | **18/19 (95%)** |
| Contain a `REDUCE` opcode (exec surface) | **17/19 (89%)** |
| Ship pickle **without** a safetensors alternative | **14/19 (74%)** |
| No published hashes to verify integrity | **19/19 (100%)** |
| No model card | **16/19 (84%)** |

Finding counts by category: `M2` = 35 (18 `pickle-present` + 17 `reduce-opcode`), `M4` = 14, `M7` = 35.
Top rules: `M7-no-hashes` (19), `M2-pickle-present` (18), `M2-reduce-opcode` (17), `M7-no-model-card`
(16), `M4-pickle-without-safetensors` (14). Full output in
[`packages/airlock/docs/CORPUS_STUDY.md`](../packages/airlock/docs/CORPUS_STUDY.md).

**Reading:** pickle-based distribution is still the norm even among reference models, and
provenance/integrity metadata is almost always absent — exactly the supply-chain surface Airlock makes
visible. (These models are *benign* — the study measures distribution/provenance hygiene, not that they
are malicious; see §6.3 for the true-negative check.)

### 6.2 Adversarial robustness — can the scanner be evaded?

**Method:** generate all 14 evasive payloads, scan each, assert every one trips code-execution (M1).
Locked in by [`packages/airlock/tests/test_adversarial.py`](../packages/airlock/tests/test_adversarial.py)
(9 tests), which fails CI if any obfuscation slips a payload past the scanner.

**Result: Airlock flags M1 on 14/14**, and additionally raises the M6 format-spoofing finding on
`disguised_safetensors`. A genuine safetensors file is verified to produce **zero** false positives.

### 6.3 Benchmark vs. picklescan / modelscan / fickling — head to head

**Method:** ask every installed scanner the same question on every pickle artifact — *do you flag code
execution?* Airlock = "any M1 finding"; picklescan = "any Dangerous global / non-zero issue"; modelscan =
"any issue in the scan summary"; fickling = "`check_safety()` severity ≥ `LIKELY_UNSAFE`". A tool that
cannot process an input (fickling does not handle zip/gzip-wrapped pickles) reports `n/a`.

```bash
pip install picklescan modelscan fickling
python packages/airlock/scripts/benchmark.py datasets/corpus.txt > packages/airlock/docs/BENCHMARK.md
```

**Results:**

| Group | Airlock | picklescan | modelscan | fickling |
| --- | :---: | :---: | :---: | :---: |
| **Adversarial** (14 evasive payloads) | **14/14** | 11/14 | 9/14 | 9/14 |
| **Real models** (18 benign `.bin`) | **0/18** | **0/18** | **0/18** | **0/18** |

**Honest reading:**
- **Airlock is the only scanner catching all 14 evasions.** Its edge is the **gzip/zlib-compressed** and
  **base64-staged** variants (it decompresses/decodes a layer before disassembling), which the others
  miss. On the disguised `.safetensors`, a *current* picklescan (1.0.5) also sniffs content and catches
  it — but only Airlock emits the explicit "format-mismatch" finding naming the disguise.
- **All four scored 0/18 on real benign models.** This true-negative parity is the number that matters
  most: catching attacks is easy if you cry wolf; *not* flagging 18 legitimate models as malware is the
  hard part. (Airlock still reports the pickle *surface* risk M2 and provenance advisories M4/M7 — a
  risk posture, not a false alarm.)

**Versions benchmarked:** `picklescan 1.0.5`, `modelscan 0.8.8`, `fickling 0.1.12`. Missing competitors
are omitted, so the benchmark runs with whatever is installed.

---

## 7. Reproducibility

From the repo root with the venv active:

```bash
# 1. Fetch the real-model corpus (~324 MB; needs network, no auth)
python packages/airlock/scripts/build_corpus.py

# 2. Corpus study
airlock study datasets/corpus.txt --format markdown

# 3. Adversarial suite (as tests)
cd packages/airlock && pytest tests/test_adversarial.py -q

# 4. Benchmark vs picklescan
pip install picklescan
python packages/airlock/scripts/benchmark.py datasets/corpus.txt
```

**Determinism notes:**
- The study/benchmark are deterministic given a fixed corpus. Exact *finding counts* depend on which
  repos successfully downloaded (the fetch tolerates 404s); the *per-model percentages* are stable.
- The corpus can drift if Hugging Face updates a repo. For a frozen study, pin revisions in
  `build_corpus.py` (`snapshot_download(..., revision=...)`).
- The benchmark scans each file **in place** and writes nothing into the corpus (see §8).

---

## 8. A bug worth documenting (and its fix)

Early benchmark runs isolated each pickle by **copying it into a new sub-directory of the model's own
folder** before scanning. Because those copies landed *inside* `datasets/corpus/`, each run's copies were
picked up by the next run — recursively — silently inflating the real-model count across runs (18 → 72 →
108 → …) and polluting the study's raw finding totals.

**Fix:** the benchmark now scans each file **in place** (the loader accepts a single file), so it never
writes into the corpus. The per-model *percentages* were never affected (they're per-model booleans), but
the raw counts were — a good reminder that **a test harness that mutates its own dataset is a bug**, and
that cross-run count drift is a symptom worth chasing, not rounding away.

---

## 9. Extending the corpus

- **More models:** add repo ids to `CANDIDATES` in `build_corpus.py` and re-run. The manifest and study
  pick them up automatically.
- **More evasion variants:** add a case to `build_adversarial_corpus` in `adversarial.py`; the test and
  benchmark consume it automatically. Keep every payload benign (an `echo` marker) — non-negotiable.
- **A different competitor:** the benchmark's `picklescan_flags_exec` is a single function; add a parallel
  one for `modelscan` or `fickling` to widen the comparison.
