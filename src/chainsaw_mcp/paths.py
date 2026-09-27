"""Filesystem sandboxing. Every path a client supplies passes through here."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

# File types chainsaw can parse. Suffix-less files (SYSTEM, SOFTWARE, $MFT) are kept too.
ARTEFACT_SUFFIXES = {".evtx", ".evt", ".json", ".jsonl", ".xml", ".hve", ".dat", ".bin", ".mft"}


class PathError(ValueError):
    """A client path is outside the allowed roots or otherwise unusable."""


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_under(raw: str, roots: Iterable[Path], *, what: str = "path") -> Path:
    """Resolve *raw* and require the real location to sit under one of *roots*.

    Relative values are tried against each root in order. Symlinks are followed
    before the containment check so links pointing outside the roots are rejected.
    """
    roots = tuple(roots)
    if not roots:
        raise PathError(f"No {what} roots are configured on the server")
    if not raw or "\x00" in raw:
        raise PathError(f"Invalid {what}")
    candidate = Path(os.path.expanduser(raw))
    candidates = [candidate] if candidate.is_absolute() else [root / candidate for root in roots]
    inside = False
    for cand in candidates:
        resolved = cand.resolve()
        if not any(_within(resolved, root) for root in roots):
            continue
        inside = True
        if resolved.exists():
            return resolved
    names = ", ".join(root.name for root in roots)
    if not inside:
        raise PathError(f"{what} {raw!r} is outside the allowed roots ({names})")
    raise PathError(f"{what} {raw!r} does not exist under the allowed roots ({names})")


def display_path(path: Path, roots: Iterable[Path]) -> str:
    """Root-relative form for output; falls back to the absolute path."""
    for root in roots:
        if _within(path, root):
            rel = path.relative_to(root)
            return f"{root.name}/{rel}" if str(rel) != "." else root.name
    return str(path)


def iter_artefacts(
    base: Path, *, pattern: str = "", limit: int | None = 200
) -> list[dict[str, object]]:
    """List regular files below *base* (or *base* itself), sorted by path."""
    needle = pattern.lower()
    found: list[dict[str, object]] = []
    if base.is_file():
        files = [base]
    else:
        # Hidden entries are never evidence; symlinks must stay inside the listed tree.
        files = sorted(
            p
            for p in base.rglob("*")
            if p.is_file()
            and not any(part.startswith(".") for part in p.relative_to(base).parts)
            and (not p.is_symlink() or _within(p.resolve(), base))
        )
    for file in files:
        if needle and needle not in str(file).lower():
            continue
        if file.suffix and file.suffix.lower() not in ARTEFACT_SUFFIXES and file != base:
            continue
        stat = file.stat()
        found.append(
            {
                "path": str(file),
                "relative": str(file.relative_to(base.parent if base.is_file() else base)),
                "bytes": stat.st_size,
                "suffix": file.suffix.lower(),
            }
        )
        if limit is not None and len(found) >= limit:
            break
    return found
