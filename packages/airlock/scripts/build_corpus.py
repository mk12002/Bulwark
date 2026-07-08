"""Download a small, curated corpus of *public* HuggingFace models for empirical testing.

These are tiny "random"/"test" models (a few MB each) that ship a real mix of
serialization formats — pickle ``.bin``, ``.safetensors``, and occasionally
ONNX/Keras — so Airlock's model scanner and the corpus study run against real
artifacts, not just fixtures. Nothing is executed; files are only downloaded.

Usage (from repo root, venv active):
    python packages/airlock/scripts/build_corpus.py

Writes model snapshots under ``datasets/corpus/<sanitized-id>/`` and a
``datasets/corpus.txt`` manifest (one ``model <path>`` per line) for
``airlock study``. The ``datasets/`` folder is gitignored.
"""

from __future__ import annotations

import sys
from pathlib import Path

# A curated list of tiny, public models. Extra candidates are included on purpose:
# some repo ids may 404 over time; the script tolerates failures and reports what
# actually landed, so the corpus stays reproducible-ish without being brittle.
CANDIDATES: list[str] = [
    "sshleifer/tiny-gpt2",
    "prajjwal1/bert-tiny",
    "hf-internal-testing/tiny-random-gpt2",
    "hf-internal-testing/tiny-random-BertModel",
    "hf-internal-testing/tiny-random-DistilBertModel",
    "hf-internal-testing/tiny-random-RobertaModel",
    "hf-internal-testing/tiny-random-t5",
    "hf-internal-testing/tiny-random-BartModel",
    "hf-internal-testing/tiny-random-GPT2LMHeadModel",
    "hf-internal-testing/tiny-random-AlbertModel",
    "hf-internal-testing/tiny-random-MobileBertModel",
    "hf-internal-testing/tiny-random-ElectraModel",
    "hf-internal-testing/tiny-random-XLMRobertaModel",
    "hf-internal-testing/tiny-random-DebertaModel",
    "hf-internal-testing/tiny-random-LlamaForCausalLM",
    "hf-internal-testing/tiny-random-MistralForCausalLM",
    "hf-internal-testing/tiny-random-GPTNeoXForCausalLM",
    "hf-internal-testing/tiny-random-OPTForCausalLM",
    "hf-internal-testing/tiny-random-BloomModel",
    "hf-internal-testing/tiny-random-CLIPModel",
    # A few small but real, widely-downloaded models to broaden the corpus beyond test repos.
    "distilbert-base-uncased",
    "prajjwal1/bert-medium",
    "prajjwal1/bert-mini",
    "google/bert_uncased_L-2_H-128_A-2",
    "hf-internal-testing/tiny-random-ViTModel",
    "hf-internal-testing/tiny-random-Wav2Vec2Model",
    "hf-internal-testing/tiny-random-GPTJForCausalLM",
    "hf-internal-testing/tiny-random-FalconForCausalLM",
    "hf-internal-testing/tiny-random-PhiForCausalLM",
    "hf-internal-testing/tiny-random-Qwen2ForCausalLM",
]

# Only pull small weight/config/code files — never gigabytes.
ALLOW = [
    "*.bin",
    "*.safetensors",
    "*.json",
    "*.h5",
    "*.keras",
    "*.onnx",
    "*.gguf",
    "*.msgpack",
    "*.py",
    "*.txt",
    "*.md",
]


def main() -> int:
    try:
        from huggingface_hub import snapshot_download
        from huggingface_hub.utils import GatedRepoError, RepositoryNotFoundError
    except ImportError:
        print("huggingface_hub not installed; run `pip install -e packages/airlock[model]`")
        return 2

    root = Path(__file__).resolve().parents[3]
    corpus_dir = root / "datasets" / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    ok: list[Path] = []
    for repo_id in CANDIDATES:
        safe = repo_id.replace("/", "__")
        dest = corpus_dir / safe
        try:
            print(f"  downloading {repo_id} ...", flush=True)
            snapshot_download(
                repo_id=repo_id,
                local_dir=str(dest),
                allow_patterns=ALLOW,
                max_workers=4,
            )
            ok.append(dest)
        except (RepositoryNotFoundError, GatedRepoError) as exc:
            print(f"    skip ({type(exc).__name__})")
        except Exception as exc:  # network hiccups, etc. — keep going
            print(f"    skip ({type(exc).__name__}: {exc})")

    manifest = root / "datasets" / "corpus.txt"
    lines = [f"model {p.as_posix()}" for p in ok]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n{len(ok)}/{len(CANDIDATES)} models downloaded -> {manifest}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
