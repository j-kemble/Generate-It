from __future__ import annotations

import os
import time
from pathlib import Path

from .constants import (
    _FILE_PICKER_CACHE_TTL_SECONDS,
    _FILE_PICKER_MAX_DEPTH,
    _FILE_PICKER_MAX_FILES,
)

# Flat modular cache — reusable, no hard-coded inline values.
_FILE_PICKER_CACHE: dict[Path, tuple[float, tuple[Path, ...]]] = {}


def _is_hidden_name(name: str) -> bool:
    """Flat helper: check hidden file/dir, reusable."""
    return name.startswith(".")


def _should_prune_depth(current_depth: int, max_depth: int) -> bool:
    """Flat helper: depth pruning decision, reusable."""
    return current_depth >= max_depth


def _walk_files_flat(
    root: Path, max_files: int, max_depth: int
) -> list[Path]:
    """Flat helper: walk and collect files, reusable."""
    files: list[Path] = []
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        dir_path = Path(dirpath)
        depth = len(dir_path.parts) - root_depth
        dirnames[:] = [d for d in dirnames if not _is_hidden_name(d)]
        if _should_prune_depth(depth, max_depth):
            dirnames[:] = []
        for filename in filenames:
            if _is_hidden_name(filename):
                continue
            files.append(dir_path / filename)
            if len(files) >= max_files:
                return files
    return files


def _collect_files_for_fuzzy(
    root_dir: Path,
    max_files: int = _FILE_PICKER_MAX_FILES,
    max_depth: int = _FILE_PICKER_MAX_DEPTH,
) -> list[Path]:
    """Collect files for fuzzy picker with short TTL cache — flat & reusable.

    Defaults come from constants, no hard-coded inline limits. Cache keeps
    data travel fast for repeated picker opens.
    """
    root = root_dir.expanduser()
    if not root.exists() or not root.is_dir():
        return []
    try:
        resolved = root.resolve()
    except OSError:
        resolved = root
    now = time.monotonic()
    cached = _FILE_PICKER_CACHE.get(resolved)
    if cached is not None:
        cached_at, cached_files = cached
        if (now - cached_at) < _FILE_PICKER_CACHE_TTL_SECONDS:
            return list(cached_files)
    files = _walk_files_flat(resolved, max_files, max_depth)
    # Bounded cache: keep at most 8 roots
    if len(_FILE_PICKER_CACHE) >= 8:
        oldest = next(iter(_FILE_PICKER_CACHE))
        del _FILE_PICKER_CACHE[oldest]
    _FILE_PICKER_CACHE[resolved] = (now, tuple(files))
    return files


def clear_file_picker_cache() -> None:
    """Clear fuzzy file cache — reusable for tests."""
    _FILE_PICKER_CACHE.clear()
