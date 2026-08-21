# Warden validation

Airlock's validation asks whether a scanner survives obfuscation of a **file**. Warden's
inputs are configs, not bytes, and its central claim is about *composition* — so the
assembly layer needs its own questions. Four studies, all deterministic, offline, and
reproducible from this repo:

```bash
python packages/warden/scripts/study.py            # all four, markdown to stdout
python packages/warden/scripts/study.py --only lexicon
```

The generated result tables are committed at [`VALIDATION_DATA.md`](VALIDATION_DATA.md);
every number below comes from that file. Nothing is hand-written.

---

## 1. Cross-framework invariance — does the IR actually abstract the framework?

Warden claims the analysis engine never has to know which framework you use: an importer
normalizes any config into one `AgentSpec`, and all analysis runs on the IR. That is a
testable claim, so it is tested. The **same logical agent** — browse the web, read a
secret, POST to a URL — was written in four framework encodings and audited.

| Importer | Capabilities recovered | A-codes | A2 fires |
| --- | --- | --- | :---: |
| `manifest` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |
| `openai_assistant` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |
| `crewai` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |
| `langchain` | browse, net_out, secret_read | A1, A2, A5, A10 | yes |

**Result: 4/4 encodings produce an identical capability set and an identical A-code set.**
The IR holds — the same risk is recovered whether the agent was declared in YAML, an
Assistants API payload, a CrewAI role file, or parsed statically out of LangChain source.

`mcp_config` is deliberately excluded rather than scored. An `.mcp.json` names *servers*,
not tools, so it cannot express a tool-level assembly at all — that is a property of the
format, and folding it into an invariance number would misreport a format limit as a
Warden result. (This is exactly the gap `--scan-parts` exists to close.)

## 2. Lexicon robustness — the honest limit

A2 depends on classifying each tool into capabilities using a keyword lexicon
([`spec/normalize.py`](../src/warden/spec/normalize.py)). If that classification fails,
the composition is invisible and the flagship finding never fires. The same kill chain was
expressed with progressively less lexical signal:

| Variant | What it changes | Capabilities recovered | A2 fires |
| --- | --- | --- | :---: |
| `explicit` | names *and* descriptions state the capability | browse, net_out, secret_read | **yes** |
| `snake_case_only` | capability in snake_case names, no descriptions | browse, net_out, secret_read | **yes** |
| `camelCase_only` | capability in camelCase names, no descriptions | browse, net_out, secret_read | **yes** |
| `opaque_names_rich_desc` | meaningless names, capability only in the description | net_out, secret_read | **yes** |
| `paraphrased` | capability described in unlisted synonyms | *none* | no |
| `scope_only` | capability implied only by scope strings | secret_read | no |
| `opaque_no_signal` | no name, description, or scope signal (the floor) | *none* | no |

**Result: A2 recovered on 4/7 variants.** This is the number most worth publishing,
because it bounds the claim honestly. Three distinct things are happening:

- **`camelCase_only` was a defect and is now fixed.** This study is what found it.
  `_tool_text()` appended an underscore/hyphen-normalized copy so `\bbrowse\b` matched
  `browse_web` — but it did not split case transitions, so `browseWeb` classified as
  `unknown` and **every camelCase assembly silently lost A2** while still reporting a
  clean-looking MEDIUM verdict. That covers most of the TypeScript MCP ecosystem. The fix
  appends a camel-split copy alongside the de-snaked one; `snake_case` and `camelCase` now
  classify identically, which is pinned by a regression test.
- **`paraphrased` and `opaque_no_signal` are the genuine ceiling** of a keyword lexicon.
  "Obtains confidential material from protected storage" is a secret read to a human and
  nothing to a regex. No amount of pattern-tuning closes this class; it is the argument for
  the optional AI layer and for reading capability from MCP tool schemas rather than prose.
- **`scope_only` partially works** — `vault/*` recovers `secret_read` — but scopes are not
  yet a first-class capability signal the way names and descriptions are.

The practical reading: **Warden is reliable when tool names or descriptions are
conventional, and degrades to silence when they are not.** It does not produce a
misleading *clean* verdict in those cases — the agent still scores on breadth and still
raises A1/A10 — but the compositional finding, the thing Warden is for, is absent. A tool
that is honest about where it stops is more useful than one that implies uniform coverage.

## 3. False positives — the lexicon's other edge

The same keyword matching that misses paraphrase can over-fire on innocent vocabulary.
Seven benign agents were built specifically around words the lexicon watches for:

| Agent | The trap | Capabilities tagged | Spurious A2 | HIGH+ |
| --- | --- | --- | :---: | :---: |
| `text_formatter` | "format" a string, not a disk | — | no | 0 |
| `calculator` | no capability vocabulary at all | — | no | 0 |
| `translator` | "transfer" meaning, not money | — | no | 0 |
| `clarifier` | "query" the user, not a database | db_read | no | 0 |
| `support_desk` | "open" a ticket, not a file | db_write | no | 1 |
| `doc_drafter` | "delete" the user's own draft | destructive, fs_write | no | 2 |
| `sandbox_mention` | "sandboxed" used reassuringly | code_exec | no | 2 |

**Result: 0/7 spurious A2, and 3/7 benign agents carry a HIGH+ finding** (down from 5/7 —
this study found two more lexicon defects and both are fixed).

The flagship compositional claim is clean: no benign agent was told it had an exfiltration
path. Two spurious classifications this study surfaced are now fixed, both following the
domain-noun idiom the lexicon already used for `format` and `open`:

- **`transfer`/`wire` → FINANCIAL** now require a money noun nearby. "Transfer the meaning
  of a phrase" was being classified as a financial operation — and FINANCIAL is
  HIGH_IMPACT, so a translation tool was also getting a spurious A3 missing-gate finding.
  ("Transfer learning" would have tripped it too.)
- **`request` → NET_OUT** now requires network context. A bare `\brequest\b` matched "the
  user's request", which is ordinary English long before it is an HTTP verb.

**Three residual taggings are left, and they are judgement calls rather than clear bugs.**
`delete_draft` really is a delete, `update_status` really is a write, and a tool that says
it "runs in a sandboxed viewer" is at least adjacent to execution. Narrowing those would
start costing true positives, so they stay. The honest summary: **the compositional layer
is precise; the capability layer under it is deliberately cautious**, and `--profile strict`
on a benign agent will still surface MEDIUM/HIGH items a human must dismiss.

## 4. Recommendation efficacy — does `--recommend` actually harden anything?

Each fixture was audited, passed through `recommend()`, and the hardened spec re-audited.

| Agent | Score | HIGH+ | Changes | Residual codes |
| --- | :---: | :---: | :---: | --- |
| `basic.yaml` | 44 → 16 | 2 → 0 | 4 | A4 |
| `exfil.yaml` | 41 → 33 | 2 → 2 | 1 | A1, A2, A5 |
| `injectable.yaml` | 85 → 57 | 7 → 4 | 5 | A1, A2, A5 |
| `crewai_agents.yaml` | 49 → 41 | 2 → 2 | 1 | A1, A2, A4, A5 |
| `openai_assistant.json` | 44 → 16 | 2 → 0 | 3 | A4 |
| `langchain_agent.py` | 52 → 24 | 2 → 0 | 3 | A1, A4 |
| `clean.yaml` | 0 → 0 | 0 → 0 | 0 | — |

**Result: across the six specs with something to harden, mean agency score falls
52.5 → 31.2 (−21.3) and HIGH+ findings fall 17 → 8.** The already-minimal `clean.yaml`
control is left untouched, which is the property that matters most — a hardening pass that
"improves" a clean agent is rewriting for its own sake.

The residual A2 on `exfil`, `injectable`, and `crewai` is **correct and deliberate**.
Warden will mechanically add gates, sandboxes, scope allow-lists, and runaway guards,
because those preserve intent. It will not delete a tool to break a toxic combination,
because that changes what the agent is *for* — so it emits an advisory instead and leaves
the decision to a human. The measurable claim is therefore narrower than "it fixes your
agent": **it removes the mechanical over-privilege and surfaces what is left as a design
decision.**

## Honesty notes

- **The kill chain is one composition.** All three composition studies are built around
  browse → secret_read → net_out. It is the canonical case and the one A2 was designed for;
  robustness numbers on other toxic pairs (financial + browse, db_write + net_in) are not
  yet measured.
- **The fixtures are authored by this project.** Studies 1, 2, and 3 use generated specs
  and study 4 uses repo fixtures — none of it is a sample of agents in the wild. The 0/7
  false-positive result says the lexicon survives seven traps chosen by the person who knew
  where the traps were; it does not estimate a false-positive rate on real configs. A corpus
  study over public agent configurations is the outstanding work, and it is what would turn
  these into population statistics.
- **n is small everywhere.** Seven variants, seven benign agents, seven fixtures. These are
  designed cases that bound behaviour, not samples that estimate it.
- **Nothing here executes.** Every "capability" is an inert string in a config; the
  LangChain encoding is parsed statically and never imported.
