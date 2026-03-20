from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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


def test_find_duplicate_credential_is_case_insensitive_and_trimmed() -> None:
    creds = [
        {"id": 10, "service": "GitHub", "username": "DevUser"},
        {"id": 11, "service": "Gmail", "username": "alice@example.com"},
    ]
    found = tui._find_duplicate_credential(creds, " github ", " devuser ")
    assert found is not None
    assert found["id"] == 10


def test_find_duplicate_credential_supports_excluding_id() -> None:
    creds = [{"id": 5, "service": "GitHub", "username": "dev"}]
    found = tui._find_duplicate_credential(creds, "github", "dev", exclude_id=5)
    assert found is None


def test_save_credential_duplicate_safe_saves_when_no_duplicate(monkeypatch) -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.saved = []
            self.updated = []

        def list_credentials(self):
            creds = [{"id": 1, "service": "GitHub", "username": "dev", "password": "old"}]
            for i, item in enumerate(self.saved, start=2):
                creds.append({"id": i, "service": item[0], "username": item[1], "password": item[2]})
            return creds

        def save_credential(self, service: str, username: str, password: str) -> int:
            self.saved.append((service, username, password))
            return 99

        def update_credential(self, credential_id: int, service: str, username: str, password: str) -> None:
            self.updated.append((credential_id, service, username, password))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui, "_run_modal", lambda *args, **kwargs: None)

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="GitLab",
        username="dev",
        password="new-pass",
    )

    assert result == "saved"
    assert storage.saved == [("GitLab", "dev", "new-pass")]
    assert storage.updated == []
    assert any(c["service"] == "GitLab" for c in state.vault_credentials)


def test_save_credential_duplicate_safe_allows_same_service_different_username(monkeypatch) -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.saved = []
            self.updated = []

        def list_credentials(self):
            creds = [{"id": 1, "service": "GitHub", "username": "dev", "password": "old"}]
            for i, item in enumerate(self.saved, start=2):
                creds.append({"id": i, "service": item[0], "username": item[1], "password": item[2]})
            return creds

        def save_credential(self, service: str, username: str, password: str) -> int:
            self.saved.append((service, username, password))
            return 99

        def update_credential(self, credential_id: int, service: str, username: str, password: str) -> None:
            self.updated.append((credential_id, service, username, password))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui, "_run_modal", lambda *args, **kwargs: None)

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="GitHub",
        username="work-account",
        password="new-pass",
    )

    assert result == "saved"
    assert storage.saved == [("GitHub", "work-account", "new-pass")]
    assert storage.updated == []


def test_save_credential_duplicate_safe_overwrites_on_confirmation(monkeypatch) -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.updated = []

        def list_credentials(self):
            return [{"id": 42, "service": "GitHub", "username": "dev", "password": "old"}]

        def save_credential(self, service: str, username: str, password: str) -> int:
            raise AssertionError("save_credential should not be called for duplicates")

        def update_credential(self, credential_id: int, service: str, username: str, password: str) -> None:
            self.updated.append((credential_id, service, username, password))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui, "_run_modal", lambda *args, **kwargs: "overwrite")

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="github",
        username="DEV",
        password="new-pass",
    )

    assert result == "overwritten"
    assert storage.updated == [(42, "github", "DEV", "new-pass")]


def test_save_credential_duplicate_safe_cancels_without_overwrite(monkeypatch) -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.saved = []
            self.updated = []

        def list_credentials(self):
            return [{"id": 42, "service": "GitHub", "username": "dev", "password": "old"}]

        def save_credential(self, service: str, username: str, password: str) -> int:
            self.saved.append((service, username, password))
            return 1

        def update_credential(self, credential_id: int, service: str, username: str, password: str) -> None:
            self.updated.append((credential_id, service, username, password))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui, "_run_modal", lambda *args, **kwargs: "cancel")

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="GitHub",
        username="dev",
        password="new-pass",
    )

    assert result == "cancelled"
    assert storage.saved == []
    assert storage.updated == []


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


def test_coerce_index_clamps_and_defaults() -> None:
    assert tui._coerce_index("3", 5, default=0) == 3
    assert tui._coerce_index("999", 5, default=0) == 4
    assert tui._coerce_index("-10", 5, default=0) == 0
    assert tui._coerce_index("bad", 5, default=2) == 2
    assert tui._coerce_index(None, 5, default=1) == 1


def test_security_option_label_helpers() -> None:
    state = tui.AppState()
    state.clipboard_auto_clear_index = 2  # 30 seconds
    state.auto_lock_index = 3  # 10 minutes

    assert tui._clipboard_auto_clear_label(state) == "30 seconds"
    assert tui._clipboard_auto_clear_seconds(state) == 30
    assert tui._auto_lock_label(state) == "10 minutes"
    assert tui._auto_lock_setting(state) == 600


def test_should_auto_lock_now_for_inactivity() -> None:
    state = tui.AppState()
    state.vault_unlocked = True
    state.auto_lock_index = 2  # 5 minutes
    state.last_activity_at = 100.0
    state.last_tick_at = 100.0

    assert tui._should_auto_lock_now(state, now=399.0) is False
    assert tui._should_auto_lock_now(state, now=401.0) is True


def test_should_auto_lock_now_for_screen_off_gap() -> None:
    state = tui.AppState()
    state.vault_unlocked = True
    state.auto_lock_index = 1  # Lock when screen off
    state.last_activity_at = 100.0
    state.last_tick_at = 100.0

    assert tui._should_auto_lock_now(state, now=110.0) is False
    assert tui._should_auto_lock_now(state, now=131.0) is True


def test_maybe_auto_clear_clipboard_clears_when_due_and_unchanged(monkeypatch) -> None:
    clipboard = {"value": "secret"}

    monkeypatch.setattr(tui.pyperclip, "paste", lambda: clipboard["value"])
    monkeypatch.setattr(tui.pyperclip, "copy", lambda text: clipboard.__setitem__("value", text))

    state = tui.AppState()
    state.clipboard_clear_due_at = 10.0
    state.clipboard_clear_expected = "secret"

    cleared = tui._maybe_auto_clear_clipboard(state, now=10.1)
    assert cleared is True
    assert clipboard["value"] == ""
    assert state.clipboard_clear_due_at is None
    assert state.clipboard_clear_expected is None


def test_maybe_auto_clear_clipboard_does_not_clear_changed_value(monkeypatch) -> None:
    clipboard = {"value": "newer-content"}

    monkeypatch.setattr(tui.pyperclip, "paste", lambda: clipboard["value"])
    monkeypatch.setattr(tui.pyperclip, "copy", lambda text: clipboard.__setitem__("value", text))

    state = tui.AppState()
    state.clipboard_clear_due_at = 10.0
    state.clipboard_clear_expected = "old-content"

    cleared = tui._maybe_auto_clear_clipboard(state, now=10.1)
    assert cleared is True
    assert clipboard["value"] == "newer-content"
