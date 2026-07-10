from __future__ import annotations

import os
from pathlib import Path


def _collect_files_for_fuzzy(root_dir: Path, max_files: int = 5000, max_depth: int = 8) -> list[Path]:
    files: list[Path] = []
    root = root_dir.expanduser()
    if not root.exists() or not root.is_dir():
        return files

    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        dir_path = Path(dirpath)
        depth = len(dir_path.parts) - root_depth
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if depth >= max_depth:
            dirnames[:] = []

        for filename in filenames:
            if filename.startswith("."):
                continue
            files.append(dir_path / filename)
            if len(files) >= max_files:
                return files
    return files
