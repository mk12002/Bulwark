"""Install community rule packs into the user rules directory (``rules update``).

A pack is only installed if it parses and validates and introduces no rule id that
collides with an already-loaded rule. Sources may be a local directory or a URL to
a ``.zip`` (fetched with ``httpx`` when the ``ai`` extra is present). This is the
mechanism behind a curated, versioned community feed — no network is required to
use it with a local source.
"""

from __future__ import annotations

import io
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from airlock.core.rules import (
    LoadedRule,
    RuleLoadError,
    load_rule_pack,
    load_rules,
    user_rules_dir,
)


@dataclass
class UpdateResult:
    """Outcome of a rules-update run."""

    installed: list[str] = field(default_factory=list)  # pack filenames installed
    skipped: list[str] = field(default_factory=list)  # (name: reason) for rejects
    dest: Path | None = None


def _existing_ids() -> set[str]:
    try:
        return {lr.rule.id for lr in load_rules()}
    except RuleLoadError:
        return set()


def _validate_pack(path: Path, known: set[str]) -> tuple[list[LoadedRule], str | None]:
    try:
        _, loaded = load_rule_pack(path)
    except RuleLoadError as exc:
        return [], f"invalid: {exc}"
    for lr in loaded:
        if lr.rule.id in known:
            return [], f"duplicate rule id {lr.rule.id!r}"
    return loaded, None


def _collect_source_packs(source: str) -> tuple[Path, bool]:
    """Return (dir_containing_packs, is_temp). Handles a dir or a .zip URL/path."""
    if source.startswith(("http://", "https://")):
        return _fetch_zip(source), True
    src = Path(source)
    if src.is_dir():
        return src, False
    if src.suffix == ".zip" and src.is_file():
        tmp = Path(_extract_zip(src.read_bytes()))
        return tmp, True
    raise RuleLoadError(f"source not found or unsupported: {source}")


def _fetch_zip(url: str) -> Path:
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuleLoadError("fetching a URL requires the 'ai' extra (httpx)") from exc
    try:
        resp = httpx.get(url, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:  # pragma: no cover - network
        raise RuleLoadError(f"could not fetch {url}: {exc}") from exc
    return Path(_extract_zip(resp.content))


def _extract_zip(data: bytes) -> str:
    import tempfile

    dest = tempfile.mkdtemp(prefix="airlock-rules-")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".yaml") and "/../" not in info.filename:
                zf.extract(info, dest)
    return dest


def update_rules(source: str, dest: Path | None = None) -> UpdateResult:
    """Validate and install ``*.yaml`` rule packs from ``source`` into ``dest``."""
    target = dest or user_rules_dir()
    target.mkdir(parents=True, exist_ok=True)
    result = UpdateResult(dest=target)
    known = _existing_ids()

    source_dir, _is_temp = _collect_source_packs(source)
    for path in sorted(source_dir.rglob("*.yaml")):
        loaded, reason = _validate_pack(path, known)
        if reason is not None:
            result.skipped.append(f"{path.name}: {reason}")
            continue
        shutil.copy2(path, target / path.name)
        known.update(lr.rule.id for lr in loaded)
        result.installed.append(path.name)
    return result
