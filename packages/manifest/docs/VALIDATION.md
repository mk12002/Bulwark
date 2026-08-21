# Manifest validation

Manifest claims to produce a **complete**, **standards-conformant**, **governable**
inventory, and to **compose** with the part- and assembly-level scanners. Each of those
four words is a separate testable claim, so each gets a study rather than an assertion:

```bash
python packages/manifest/scripts/study.py
```

The generated result tables are committed at [`VALIDATION_DATA.md`](VALIDATION_DATA.md);
every number below comes from that file. All studies run with `offline=True`, so there is
no network I/O and the numbers are stable in CI.

---

## 1. Discovery recall — does the inventory miss anything?

An inventory tool that silently omits a component is worse than no inventory, because the
gap is invisible: you cannot audit what was never listed. Ground truth for both fixture
projects was written **by hand from the file trees**, not from Manifest's own output — a
self-comparison would only prove the tool agrees with itself.

| Project | Expected | Found | Recall | Missed |
| --- | :---: | :---: | :---: | --- |
| `sample_project_clean` | 4 | 4 | 100% | — |
| `sample_project_risky` | 11 | 11 | 100% | — |

**Result: 15/15 components discovered (100% recall), with no unexplained extras.**

The risky project is the interesting one, because most of its components are not in
`requirements.txt` at all — they are embedded in code and notebooks, which is where real
projects hide their dependencies:

| Component | Present in the fixture as | Typed as |
| --- | --- | --- |
| `transformers` | `requirements.txt` (unpinned) | framework |
| `pyyaml`, `openai` | `requirements.txt` | library / framework |
| `torch`, `datasets` | `explore.ipynb` — a `!pip install` line | library |
| `google/flan-t5-small` | `explore.ipynb` — a `from_pretrained()` call | machine-learning-model |
| `imdb` | `explore.ipynb` — a `load_dataset()` call | data |
| `train.csv` | `data/` on disk | data |
| `model.safetensors`, `pytorch_model.bin` | `model/` weights | machine-learning-model |
| `system_prompt` | `agent.yaml` — an embedded prompt | data |

Recovering a hub model from a `from_pretrained()` call and a dataset from `load_dataset()`
inside a notebook is the substantive result here: a dependency scanner that reads only
`requirements.txt` would report 3 of these 11 components and call the project inventoried.

Recall is measured on component **identity**, not type. Whether `torch` is a `library` or a
`framework` is a modelling choice — Manifest calls it a framework in one project and a
library in the other depending on where it was found — so the type assignment is reported
alongside rather than folded into the recall number, where it would read as a miss.

## 2. BOM conformance — is "standards-based" true?

"Standards-based" is this project's most-repeated claim and the cheapest one to get subtly
wrong: a document that *looks* like CycloneDX but uses an invalid component type or a
dangling dependency ref will be rejected by the tools that matter.

| Check | CycloneDX | SPDX |
| --- | :---: | :---: |
| Document required fields present | pass | pass |
| Format/version identifier correct | pass | pass |
| Document identifier well-formed | pass (`urn:uuid:…`) | pass (`SPDXRef-DOCUMENT`) |
| Every component/package has its required fields | pass (11) | pass (11) |
| Component types within the spec's enum | pass | n/a |
| Package identifiers use the `SPDXRef-` prefix | n/a | pass |
| Dependency refs resolve to a real component | pass | n/a |

**Result: 10/10 conformance checks pass on both formats.** The types actually emitted —
`data`, `framework`, `library`, `machine-learning-model` — are all valid CycloneDX
component types, including the ML-BOM-specific one.

This is a **required-field and well-formedness check against the specs' documented rules,
not full JSON-Schema validation** against the upstream schema documents. Fetching those
would make the study non-hermetic and CI network-dependent. Schema validation against a
vendored copy of the CycloneDX and SPDX schemas is a worthwhile strengthening and is not
yet done — the current result should be read as "structurally conformant", which is
weaker than "schema-valid".

## 3. Governance coverage — is the control map load-bearing?

A control mapping with no findings underneath it is decoration. This measures how much of
each framework a single real scan actually exercises.

| Framework | Controls | Exercised | Breakdown |
| --- | :---: | :---: | --- |
| NIST AI RMF | 4 | 3 | GOVERN (8), MAP (7), MEASURE (2), MANAGE (0) |
| EU AI Act | 6 | 5 | Art.10 (6), Art.11 (6), Art.12 (4), Art.13 (5), Art.15 (2), Art.14 (0) |

Every B-code the project produced maps to at least one control — B1, B3, B4, B6, B7, B8,
and B9 all land somewhere, so no finding is orphaned from the governance view.

**The two zeros are the honest part, and they are structural rather than accidental.** NIST
`MANAGE` and EU `Art.14 Human oversight` are both about *organizational process* — who
reviews, who signs off, what happens when a risk is accepted. A static scan of a directory
has nothing to say about either, and a tool that claimed coverage there would be
manufacturing evidence. They are mapped so the gap is visible in the report rather than
silently absent from it.

## 4. Risk-bridge fidelity — does composition preserve findings?

`manifest scan --scan-risk` runs Airlock on discovered model/MCP components and Warden on
discovered agent assemblies, folding their findings in as B5. This is the suite's central
composition claim, so its two failure modes — silently dropping part-level findings, and
double-counting them — are measured directly.

| Metric | Value |
| --- | --- |
| Baseline findings (no `--scan-risk`) | 14 across 6 B-codes |
| Bridged findings (`--scan-risk`) | 21 across 10 codes |
| B5 risk findings folded in | 1 |
| Baseline codes preserved under bridging | all — none lost |
| Duplicate `(rule, location)` pairs | 0 of 21 |
| Bridged findings carry a severity | all (max: HIGH) |

**Result: 6/6 bridge checks pass.** Bridging is purely additive — every code present in the
baseline scan survives, seven findings are gained, and no `(rule, location)` pair appears
twice. Note that a finding `id` legitimately repeats across components (`B1-unpinned` fires
once per unpinned dependency), so uniqueness is measured on the `(rule, location)` instance
key rather than on `id` alone.

## Honesty notes

- **n = 2 projects.** This is the load-bearing limitation. Both fixtures were written by
  this project, by someone who knew what the discoverers look for. 100% recall means "no
  gaps in two small, authored trees" — it is a regression guarantee, not an estimate of
  recall on real repositories. A corpus study over public ML projects is the outstanding
  work and is the only thing that would make this a population claim.
- **Recall, not precision.** Ground truth names what *should* be found. Because nothing
  unexpected was reported on these two projects, there is no false-positive measurement
  here at all — a noisier real project could produce spurious components and this study
  would not detect it.
- **Offline mode skips resolvers.** With `offline=True`, OSV vulnerability lookup and
  license resolution do not run, so B-codes depending on them are underrepresented. The
  governance numbers describe an offline scan specifically.
- **Structural conformance, not schema validation.** See study 2 — the distinction is real
  and the weaker claim is the accurate one.
