"""AI-BOM drift: diff two BOMs to see what components were added/removed/changed.

Governance is a moving target — a model gets swapped, a dependency bumped, an MCP
server added. Diff mode surfaces exactly what changed between two scans so a review
focuses on the delta, not the whole inventory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from manifest.bom.model import AIBOM, Component


@dataclass
class BomDiff:
    added: list[Component] = field(default_factory=list)
    removed: list[Component] = field(default_factory=list)
    changed: list[tuple[Component, Component]] = field(default_factory=list)  # (old, new)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def render(self) -> str:
        lines = ["# AI-BOM drift", ""]
        lines.append(f"- added:   {len(self.added)}")
        lines.append(f"- removed: {len(self.removed)}")
        lines.append(f"- changed: {len(self.changed)}")
        lines.append("")
        for c in self.added:
            lines.append(f"+ {c.type.value}: {c.name} ({c.provenance.version or 'unversioned'})")
        for c in self.removed:
            lines.append(f"- {c.type.value}: {c.name} ({c.provenance.version or 'unversioned'})")
        for old, new in self.changed:
            lines.append(
                f"~ {new.type.value}: {new.name} "
                f"[{_ver(old)} -> {_ver(new)}; {_lic(old)} -> {_lic(new)}]"
            )
        return "\n".join(lines) + "\n"


def _ver(c: Component) -> str:
    return c.provenance.version or c.provenance.hash or "?"


def _lic(c: Component) -> str:
    return c.license.id or c.license.risk


def _signature(c: Component) -> tuple[str, str]:
    """A per-component identity that ignores version (name+type) for change detection."""
    return (c.type.value, c.name)


def _attrs(c: Component) -> tuple:
    """The fields whose change makes a same-key component 'changed'."""
    return (c.provenance.version, c.provenance.hash, c.license.id, c.license.risk)


def diff_boms(old: AIBOM, new: AIBOM) -> BomDiff:
    """Diff two AIBOMs by key (attribute changes) then by (type,name) (version bumps)."""
    old_by_key = {c.key: c for c in old.components}
    new_by_key = {c.key: c for c in new.components}

    diff = BomDiff()
    handled_added: set[str] = set()
    handled_removed: set[str] = set()

    # 1) Same key, different attributes (e.g. a re-licensed model) → changed.
    for key in old_by_key.keys() & new_by_key.keys():
        old_c, new_c = old_by_key[key], new_by_key[key]
        if _attrs(old_c) != _attrs(new_c):
            diff.changed.append((old_c, new_c))

    # 2) Same (type, name), different key (e.g. a version bump) → changed.
    old_by_sig = {_signature(c): c for c in old.components}
    new_by_sig = {_signature(c): c for c in new.components}
    for sig, moved_new in new_by_sig.items():
        moved_old = old_by_sig.get(sig)
        if moved_old is not None and moved_old.key != moved_new.key:
            diff.changed.append((moved_old, moved_new))
            handled_added.add(moved_new.key)
            handled_removed.add(moved_old.key)

    diff.added = [
        new_by_key[k]
        for k in sorted(new_by_key.keys() - old_by_key.keys())
        if k not in handled_added
    ]
    diff.removed = [
        old_by_key[k]
        for k in sorted(old_by_key.keys() - new_by_key.keys())
        if k not in handled_removed
    ]
    return diff
