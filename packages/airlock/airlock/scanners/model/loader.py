"""Target resolution and artifact discovery for the model scanner.

Accepts a local path (file or directory) or an ``hf:org/name`` reference. For HF
references, only the files needed for scanning are downloaded (configs, weights,
custom Python). Nothing is ever executed or deserialized here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# File-extension groups used across the model analyzers.
PICKLE_EXTENSIONS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill"}
SAFETENSORS_EXTENSIONS = {".safetensors"}
# Memory-safe serialization formats (no code execution on load).
SAFE_FORMAT_EXTENSIONS = SAFETENSORS_EXTENSIONS | {".gguf", ".ggml"}
CONFIG_EXTENSIONS = {".json"}
CODE_EXTENSIONS = {".py"}
# numpy arrays: object dtype embeds a pickle.
NUMPY_EXTENSIONS = {".npy", ".npz"}
# Keras/TF: HDF5 or the v3 zip container; Lambda layers embed Python.
KERAS_EXTENSIONS = {".h5", ".hdf5", ".keras"}
ONNX_EXTENSIONS = {".onnx"}

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
    files = [_artifact_file(p, root) for p in sorted(root.rglob("*")) if p.is_file()]
    return ModelInventory(target=path_str, root=root, files=files)


def _resolve_hf(repo_id: str) -> ModelInventory:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ResolveError(
            "huggingface_hub is required for hf: targets. Install with "
            "'pip install airlock[model]'."
        ) from exc
    try:
        local = snapshot_download(repo_id=repo_id, allow_patterns=_HF_ALLOW_PATTERNS)
    except Exception as exc:  # pragma: no cover - network/hub errors
        raise ResolveError(f"could not fetch hf:{repo_id}: {exc}") from exc
    root = Path(local)
    files = [_artifact_file(p, root) for p in sorted(root.rglob("*")) if p.is_file()]
    return ModelInventory(target=f"hf:{repo_id}", root=root, files=files)


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
