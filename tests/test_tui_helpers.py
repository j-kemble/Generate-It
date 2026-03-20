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


def test_filter_vault_credentials_blank_query_returns_all() -> None:
    creds = [
        {"id": 1, "service": "GitHub", "username": "octocat"},
        {"id": 2, "service": "Gmail", "username": "alice@example.com"},
    ]

    filtered = tui._filter_vault_credentials(creds, "   ")
    assert filtered == creds


def test_filter_vault_credentials_matches_service_or_username_case_insensitive() -> None:
    creds = [
        {"id": 1, "service": "GitHub", "username": "octocat"},
        {"id": 2, "service": "Gmail", "username": "alice@example.com"},
        {"id": 3, "service": "Bitwarden", "username": "Bob"},
    ]

    filtered_service = tui._filter_vault_credentials(creds, "git")
    assert [c["id"] for c in filtered_service] == [1]

    filtered_user = tui._filter_vault_credentials(creds, "ALICE@")
    assert [c["id"] for c in filtered_user] == [2]

    filtered_none = tui._filter_vault_credentials(creds, "not-found")
    assert filtered_none == []


def test_filter_vault_credentials_ranks_best_match_first() -> None:
    creds = [
        {"id": 1, "service": "Gmail", "username": "foo"},
        {"id": 2, "service": "GitHub", "username": "octocat"},
        {"id": 3, "service": "Bitwarden", "username": "gh-user"},
    ]

    filtered = tui._filter_vault_credentials(creds, "git")
    assert [c["id"] for c in filtered] == [2]


def test_filter_vault_credentials_supports_subsequence_match() -> None:
    creds = [
        {"id": 1, "service": "Azure", "username": "devops"},
        {"id": 2, "service": "Bitbucket", "username": "team"},
    ]

    filtered = tui._filter_vault_credentials(creds, "azr")
    assert [c["id"] for c in filtered] == [1]


def test_handle_double_esc_quit_requires_two_presses_within_window() -> None:
    should_quit, last_esc = tui._handle_double_esc_quit(
        key=27,
        last_esc_at=None,
        now=100.0,
        window_seconds=1.0,
    )
    assert should_quit is False
    assert last_esc == 100.0

    should_quit, last_esc = tui._handle_double_esc_quit(
        key=27,
        last_esc_at=last_esc,
        now=100.8,
        window_seconds=1.0,
    )
    assert should_quit is True
    assert last_esc is None


def test_handle_double_esc_quit_expires_after_window() -> None:
    should_quit, last_esc = tui._handle_double_esc_quit(
        key=27,
        last_esc_at=10.0,
        now=11.5,
        window_seconds=1.0,
    )
    assert should_quit is False
    assert last_esc == 11.5


def test_handle_double_esc_quit_non_esc_clears_state() -> None:
    should_quit, last_esc = tui._handle_double_esc_quit(
        key=ord("a"),
        last_esc_at=50.0,
        now=50.1,
        window_seconds=1.0,
    )
    assert should_quit is False
    assert last_esc is None
