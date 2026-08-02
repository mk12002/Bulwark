"""Discovery context + registry. Discoverers parse statically — never execute code."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from bulwark_core.limits import walk_files

from manifest.bom.model import Component

_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".tox",
}
_MAX_READ_BYTES = 512 * 1024  # cap per-file text reads


@dataclass
class DiscoveryContext:
    """The scanned project: its root and the discovered files."""

    root: Path
    files: list[Path] = field(default_factory=list)

    @classmethod
    def build(cls, root: Path) -> DiscoveryContext:
        """Walk the project once: bounded, symlink-contained, and skipping noise dirs.

        ``walk_files`` provides the file cap and the containment check (a project
        containing a symlink to ``/`` must not make discovery traverse the filesystem);
        ``_SKIP_DIRS`` then removes virtualenvs, VCS, and build output, without which
        the BOM would inventory every installed dependency's example code.
        """
        files = [
            p
            for p in walk_files(root)
            if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
        ]
        return cls(root=root, files=files)

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(path)

    def read_text(self, path: Path) -> str:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                return fh.read(_MAX_READ_BYTES)
        except OSError:
            return ""

    def by_name(self, *names: str) -> list[Path]:
        wanted = {n.lower() for n in names}
        return [p for p in self.files if p.name.lower() in wanted]

    def by_suffix(self, *suffixes: str) -> list[Path]:
        wanted = {s.lower() for s in suffixes}
        return [p for p in self.files if p.suffix.lower() in wanted]

    def code_files(self) -> list[Path]:
        return self.by_suffix(".py", ".ipynb", ".js", ".ts", ".mjs")


Discoverer = Callable[[DiscoveryContext], list[Component]]

_REGISTRY: list[tuple[str, Discoverer]] = []


def register(name: str, fn: Discoverer) -> None:
    global _REGISTRY
    _REGISTRY = [(n, f) for (n, f) in _REGISTRY if n != name]
    _REGISTRY.append((name, fn))


def registered() -> list[tuple[str, Discoverer]]:
    return list(_REGISTRY)
