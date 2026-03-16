from __future__ import annotations

from pathlib import Path

from generate_it import tui


def test_truncate_middle_behaviour() -> None:
    assert tui._truncate_middle("short", 10) == "short"
    assert tui._truncate_middle("abcdef", 3) == "abc"
    assert tui._truncate_middle("abcdefghijklmnopqrstuvwxyz", 11) == "abcd...wxyz"


def test_fuzzy_score_basic_cases() -> None:
    # Empty query should match everything with neutral score.
    assert tui._fuzzy_score("", "foo/bar.txt") == 0

    # Direct substring scores lower (better) than subsequence fallback.
    direct = tui._fuzzy_score("bar", "foo/bar.txt")
    subseq = tui._fuzzy_score("brt", "foo/bar.txt")
    assert direct is not None
    assert subseq is not None
    assert direct < subseq

    # Non-match returns None.
    assert tui._fuzzy_score("zzz", "foo/bar.txt") is None


def test_resolve_start_dir_cases(tmp_path: Path) -> None:
    child_dir = tmp_path / "subdir"
    child_dir.mkdir()
    file_path = child_dir / "item.csv"
    file_path.write_text("name,username,password\nx,y,z\n", encoding="utf-8")

    # Existing dir stays dir.
    assert tui._resolve_start_dir(str(child_dir)) == child_dir
    # Existing file resolves to parent dir.
    assert tui._resolve_start_dir(str(file_path)) == child_dir
    # Empty path resolves to cwd.
    assert tui._resolve_start_dir("") == Path.cwd()


def test_collect_files_for_fuzzy_filters_hidden_and_depth(tmp_path: Path) -> None:
    (tmp_path / "visible").mkdir()
    (tmp_path / ".hidden_dir").mkdir()
    (tmp_path / "visible" / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / ".hidden_file.txt").write_text("h", encoding="utf-8")
    (tmp_path / ".hidden_dir" / "secret.txt").write_text("s", encoding="utf-8")

    files = tui._collect_files_for_fuzzy(tmp_path, max_files=100, max_depth=4)
    paths = {str(p.relative_to(tmp_path)).replace("\\", "/") for p in files}

    assert "visible/a.txt" in paths
    assert ".hidden_file.txt" not in paths
    assert ".hidden_dir/secret.txt" not in paths
