"""Target resolution and artifact discovery for the model scanner.

Accepts a local path (file or directory) or an ``hf:org/name`` reference. For HF
references, only the files needed for scanning are downloaded (configs, weights,
custom Python). Nothing is ever executed or deserialized here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from bulwark_core.limits import walk_files
from bulwark_core.logging import get_logger

_log = get_logger(__name__)

# File-extension groups used across the model analyzers.
PICKLE_EXTENSIONS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill"}
SAFETENSORS_EXTENSIONS = {".safetensors"}
# Memory-safe serialization formats (no code execution on load).
# safetensors, GGUF/GGML (llama.cpp), Flax/JAX msgpack, and PMML (XML) are all
# tensor/data-only formats with no executable opcodes.
SAFE_FORMAT_EXTENSIONS = SAFETENSORS_EXTENSIONS | {".gguf", ".ggml", ".msgpack", ".pmml"}
CONFIG_EXTENSIONS = {".json"}
CODE_EXTENSIONS = {".py"}
# numpy arrays: object dtype embeds a pickle.
NUMPY_EXTENSIONS = {".npy", ".npz"}
# Keras/TF: HDF5 or the v3 zip container; Lambda layers embed Python.
KERAS_EXTENSIONS = {".h5", ".hdf5", ".keras"}
ONNX_EXTENSIONS = {".onnx"}
# TensorFlow SavedModel / frozen graph protobuf; may reference custom/py_func ops.
TF_EXTENSIONS = {".pb"}

# Patterns of interest for a partial HF download.
_HF_ALLOW_PATTERNS = [
    "*.json",
    "*.bin",
    "*.pt",
    "*.pth",
    "*.ckpt",
    "*.pkl",
    "*.pickle",
    "*.joblib",
    "*.safetensors",
    "*.gguf",
    "*.npy",
    "*.npz",
    "*.h5",
    "*.hdf5",
    "*.keras",
    "*.onnx",
    "*.pb",
    "*.msgpack",
    "*.pmml",
    "*.py",
    "*.md",
    "*.txt",
]


@dataclass
class ArtifactFile:
    """One discovered file in a model artifact."""

    path: Path
    relpath: str
    size: int
    suffix: str

    @property
    def is_pickle(self) -> bool:
        return self.suffix in PICKLE_EXTENSIONS

    @property
    def is_safetensors(self) -> bool:
        return self.suffix in SAFETENSORS_EXTENSIONS

    @property
    def is_safe_format(self) -> bool:
        return self.suffix in SAFE_FORMAT_EXTENSIONS

    @property
    def is_numpy(self) -> bool:
        return self.suffix in NUMPY_EXTENSIONS

    @property
    def is_keras(self) -> bool:
        return self.suffix in KERAS_EXTENSIONS

    @property
    def is_onnx(self) -> bool:
        return self.suffix in ONNX_EXTENSIONS

    @property
    def is_tensorflow(self) -> bool:
        return self.suffix in TF_EXTENSIONS

    @property
    def is_config(self) -> bool:
        return self.suffix in CONFIG_EXTENSIONS

    @property
    def is_code(self) -> bool:
        return self.suffix in CODE_EXTENSIONS


@dataclass
class ModelInventory:
    """The resolved artifact: a root plus the files discovered under it."""

    target: str
    root: Path
    files: list[ArtifactFile] = field(default_factory=list)
    # Set when an ``hf:org/name@revision`` target pinned an immutable commit.
    revision: str | None = None
    pinned: bool = False

    def pickles(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_pickle]

    def safetensors(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_safetensors]

    def safe_formats(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_safe_format]

    def numpy_files(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_numpy]

    def keras_files(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_keras]

    def onnx_files(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_onnx]

    def configs(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_config]

    def code_files(self) -> list[ArtifactFile]:
        return [f for f in self.files if f.is_code]


class ResolveError(Exception):
    """Raised when a model target cannot be resolved."""


def resolve(target: str) -> ModelInventory:
    """Resolve a target string into a :class:`ModelInventory`.

    ``hf:org/name`` downloads the relevant files from the Hugging Face Hub; any
    other string is treated as a local path.
    """
    if target.startswith("hf:"):
        return _resolve_hf(target[len("hf:") :])
    return _resolve_local(target)


def _resolve_local(path_str: str) -> ModelInventory:
    root = Path(path_str).expanduser()
    if not root.exists():
        raise ResolveError(f"path does not exist: {root}")
    if root.is_file():
        files = [_artifact_file(root, root.parent)]
        return ModelInventory(target=path_str, root=root.parent, files=files)
    # Bounded, symlink-contained walk — a hostile artifact directory must not be able
    # to make the scan traverse the whole filesystem (see bulwark_core.limits).
    files = [_artifact_file(p, root) for p in walk_files(root)]
    _log.info("resolved local target %s: %d file(s)", path_str, len(files))
    return ModelInventory(target=path_str, root=root, files=files)


def _resolve_hf(repo_ref: str) -> ModelInventory:
    """Resolve ``org/name`` or ``org/name@revision`` from the Hugging Face Hub.

    A bare repo id resolves against a mutable git branch: the publisher can force-push
    and change the weights under you, so a scan of ``org/name`` is not reproducible.
    Passing ``@<revision>`` pins to an immutable commit and makes the scan result
    attributable to specific bytes — the model-side equivalent of a lockfile entry.
    """
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ResolveError(
            "huggingface_hub is required for hf: targets. Install with "
            "'pip install airlock[model]'."
        ) from exc

    raw_id, _, raw_revision = repo_ref.partition("@")
    repo_id = raw_id.strip()
    revision: str | None = raw_revision.strip() or None
    if not repo_id:
        raise ResolveError(f"empty repo id in hf:{repo_ref}")

    try:
        local = snapshot_download(
            repo_id=repo_id,
            revision=revision,
            allow_patterns=_HF_ALLOW_PATTERNS,
        )
    except Exception as exc:  # pragma: no cover - network/hub errors
        raise ResolveError(f"could not fetch hf:{repo_ref}: {exc}") from exc

    root = Path(local)
    files = [_artifact_file(p, root) for p in walk_files(root)]
    return ModelInventory(
        target=f"hf:{repo_ref}", root=root, files=files, revision=revision, pinned=bool(revision)
    )


def _artifact_file(path: Path, root: Path) -> ArtifactFile:
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    return ArtifactFile(
        path=path,
        relpath=rel,
        size=path.stat().st_size,
        suffix=path.suffix.lower(),
    )
