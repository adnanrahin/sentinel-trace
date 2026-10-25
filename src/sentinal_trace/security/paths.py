from __future__ import annotations

import os
from pathlib import Path


class PathSecurityError(ValueError):
    pass


def resolve_within(path: str | Path, root: str | Path) -> Path:
    """Resolve path and require it to stay inside root (no traversal, no symlink escape)."""
    root_resolved = Path(root).resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_resolved / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise PathSecurityError(f"path escapes configured root: {path}") from exc
    return resolved


def is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def iter_files(root: Path, *, follow_symlinks: bool = False) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        current = Path(dirpath)
        if not follow_symlinks:
            dirnames[:] = [d for d in dirnames if not (current / d).is_symlink()]
        for name in filenames:
            file_path = current / name
            if not follow_symlinks and file_path.is_symlink():
                continue
            files.append(file_path)
    return files
