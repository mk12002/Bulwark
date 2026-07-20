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

from bulwark_core.limits import DEFAULT_LIMITS, Limits
from bulwark_core.rules import (
    LoadedRule,
    RuleLoadError,
    load_rule_pack,
)


@dataclass
class UpdateResult:
    """Outcome of a rules-update run."""

    installed: list[str] = field(default_factory=list)  # pack filenames installed
    skipped: list[str] = field(default_factory=list)  # (name: reason) for rejects
    dest: Path | None = None


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


def _extract_zip(data: bytes, limits: Limits = DEFAULT_LIMITS) -> str:
    """Extract only ``.yaml`` rule packs from an untrusted zip, safely.

    A rules feed is remote/untrusted input, so this defends against the usual zip
    attacks: **zip-slip** (a member path resolving outside the temp dir — rejected by
    a resolved-path containment check, which catches ``../`` *and* absolute/drive
    paths that ``zf.extract`` or a naive substring check would miss), a **decompression
    bomb** (per-member and total uncompressed-size caps), and **member floods** (a
    member-count cap). Members are streamed to disk, never ``zf.extract``-ed.
    """
    import tempfile

    dest = Path(tempfile.mkdtemp(prefix="airlock-rules-"))
    dest_resolved = dest.resolve()
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for idx, info in enumerate(zf.infolist()):
            if idx >= limits.max_archive_members:
                break
            if info.is_dir() or not info.filename.lower().endswith(".yaml"):
                continue
            if info.file_size > limits.max_member_bytes:
                continue  # oversized member — skip (bomb guard)
            total += info.file_size
            if total > limits.max_uncompressed_bytes:
                break  # total uncompressed budget exceeded — stop
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest_resolved):
                continue  # zip-slip: member escapes the extraction dir — skip
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, length=64 * 1024)
    return str(dest)


def update_rules(source: str, dest: Path, known_ids: set[str] | None = None) -> UpdateResult:
    """Validate and install ``*.yaml`` rule packs from ``source`` into ``dest``.

    ``known_ids`` are the rule ids already loaded by the calling tool; any pack
    that would collide with them (or with an earlier-installed pack) is skipped.
    """
    target = dest
    target.mkdir(parents=True, exist_ok=True)
    result = UpdateResult(dest=target)
    known = set(known_ids or set())

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
