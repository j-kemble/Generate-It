from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from generate_it import tui
from generate_it import tui_files
from generate_it import tui_modal
from generate_it import tui_helpers


def test_truncate_middle_behaviour() -> None:
    assert tui_helpers._truncate_middle("short", 10) == "short"
    assert tui_helpers._truncate_middle("abcdef", 3) == "abc"
    assert tui_helpers._truncate_middle("abcdefghijklmnopqrstuvwxyz", 11) == "abcd...wxyz"


def test_fuzzy_score_basic_cases() -> None:
    # Empty query should match everything with neutral score.
    assert tui_helpers._fuzzy_score("", "foo/bar.txt") == 0

    # Direct substring scores lower (better) than subsequence fallback.
    direct = tui_helpers._fuzzy_score("bar", "foo/bar.txt")
    subseq = tui_helpers._fuzzy_score("brt", "foo/bar.txt")
    assert direct is not None
    assert subseq is not None
    assert direct < subseq

    # Non-match returns None.
    assert tui_helpers._fuzzy_score("zzz", "foo/bar.txt") is None


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

    files = tui_files._collect_files_for_fuzzy(tmp_path, max_files=100, max_depth=4)
    paths = {str(p.relative_to(tmp_path)).replace("\\", "/") for p in files}

    assert "visible/a.txt" in paths
    assert ".hidden_file.txt" not in paths
    assert ".hidden_dir/secret.txt" not in paths


def test_filter_vault_credentials_blank_query_returns_all() -> None:
    creds = [
        {"id": 1, "service": "GitHub", "username": "octocat"},
        {"id": 2, "service": "Gmail", "username": "alice@example.com"},
    ]

    filtered = tui_helpers._filter_vault_credentials(creds, "   ")
    assert filtered == creds


def test_filter_vault_credentials_matches_service_or_username_case_insensitive() -> None:
    creds = [
        {"id": 1, "service": "GitHub", "username": "octocat"},
        {"id": 2, "service": "Gmail", "username": "alice@example.com"},
        {"id": 3, "service": "Bitwarden", "username": "Bob"},
    ]

    filtered_service = tui_helpers._filter_vault_credentials(creds, "git")
    assert [c["id"] for c in filtered_service] == [1]

    filtered_user = tui_helpers._filter_vault_credentials(creds, "ALICE@")
    assert [c["id"] for c in filtered_user] == [2]

    filtered_none = tui_helpers._filter_vault_credentials(creds, "not-found")
    assert filtered_none == []


def test_filter_vault_credentials_ranks_best_match_first() -> None:
    creds = [
        {"id": 1, "service": "Gmail", "username": "foo"},
        {"id": 2, "service": "GitHub", "username": "octocat"},
        {"id": 3, "service": "Bitwarden", "username": "gh-user"},
    ]

    filtered = tui_helpers._filter_vault_credentials(creds, "git")
    assert [c["id"] for c in filtered] == [2]


def test_filter_vault_credentials_supports_subsequence_match() -> None:
    creds = [
        {"id": 1, "service": "Azure", "username": "devops"},
        {"id": 2, "service": "Bitbucket", "username": "team"},
    ]

    filtered = tui_helpers._filter_vault_credentials(creds, "azr")
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

        def list_credential_metadata(self):
            return [{"id": c["id"], "service": c["service"], "username": c["username"]} for c in self.list_credentials()]

        def find_credential_by_identity(self, service, username, exclude_id=None):
            return tui_helpers._find_duplicate_credential(
                self.list_credential_metadata(), service, username, exclude_id=exclude_id
            )

        def save_credential(self, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> int:
            self.saved.append((service, username, password, note, note_is_hidden))
            return 99

        def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> None:
            self.updated.append((credential_id, service, username, password, note, note_is_hidden))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui_modal, "_run_modal", lambda *args, **kwargs: None)

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="GitLab",
        username="dev",
        password="new-pass",
    )

    assert result == "saved"
    assert storage.saved == [("GitLab", "dev", "new-pass", "", False)]
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

        def list_credential_metadata(self):
            return [{"id": c["id"], "service": c["service"], "username": c["username"]} for c in self.list_credentials()]

        def find_credential_by_identity(self, service, username, exclude_id=None):
            return tui_helpers._find_duplicate_credential(
                self.list_credential_metadata(), service, username, exclude_id=exclude_id
            )

        def save_credential(self, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> int:
            self.saved.append((service, username, password, note, note_is_hidden))
            return 99

        def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> None:
            self.updated.append((credential_id, service, username, password, note, note_is_hidden))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui_modal, "_run_modal", lambda *args, **kwargs: None)

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="GitHub",
        username="work-account",
        password="new-pass",
    )

    assert result == "saved"
    assert storage.saved == [("GitHub", "work-account", "new-pass", "", False)]
    assert storage.updated == []


def test_save_credential_duplicate_safe_overwrites_on_confirmation(monkeypatch) -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.updated = []

        def list_credentials(self):
            return [{"id": 42, "service": "GitHub", "username": "dev", "password": "old"}]

        def list_credential_metadata(self):
            return [{"id": 42, "service": "GitHub", "username": "dev"}]

        def find_credential_by_identity(self, service, username, exclude_id=None):
            return tui_helpers._find_duplicate_credential(
                self.list_credential_metadata(), service, username, exclude_id=exclude_id
            )

        def save_credential(self, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> int:
            raise AssertionError("save_credential should not be called for duplicates")

        def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> None:
            self.updated.append((credential_id, service, username, password, note, note_is_hidden))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui_modal, "_run_modal", lambda *args, **kwargs: "overwrite")

    result = tui._save_credential_duplicate_safe(
        stdscr,
        theme,
        state,
        service="github",
        username="DEV",
        password="new-pass",
    )

    assert result == "overwritten"
    assert storage.updated == [(42, "github", "DEV", "new-pass", "", False)]


def test_save_credential_duplicate_safe_cancels_without_overwrite(monkeypatch) -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.saved = []
            self.updated = []

        def list_credentials(self):
            return [{"id": 42, "service": "GitHub", "username": "dev", "password": "old"}]

        def list_credential_metadata(self):
            return [{"id": 42, "service": "GitHub", "username": "dev"}]

        def find_credential_by_identity(self, service, username, exclude_id=None):
            return tui_helpers._find_duplicate_credential(
                self.list_credential_metadata(), service, username, exclude_id=exclude_id
            )

        def save_credential(self, service: str, username: str, password: str, note: str = "") -> int:
            self.saved.append((service, username, password, note))
            return 99

        def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "") -> None:
            self.updated.append((credential_id, service, username, password, note))

    storage = FakeStorage()
    state = SimpleNamespace(storage=storage, vault_credentials=[])
    theme = object()
    stdscr = object()

    monkeypatch.setattr(tui_modal, "_run_modal", lambda *args, **kwargs: "cancel")

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


def test_fuzzy_score_edge_cases() -> None:
    assert tui_helpers._fuzzy_score("", "hello") == 0
    assert tui_helpers._fuzzy_score("a", "A") == 0
    assert tui_helpers._fuzzy_score("abc", "abcdef") == 3
    assert tui_helpers._fuzzy_score("xyz", "abc") is None


def test_filter_vault_credentials_empty_list() -> None:
    result = tui_helpers._filter_vault_credentials([], "query")
    assert result == []


def test_filter_vault_credentials_special_characters() -> None:
    creds = [
        {"id": 1, "service": "GitHub", "username": "dev@test.com", "password": "pass"},
        {"id": 2, "service": "Test (Org)", "username": "user", "password": "pass"},
    ]
    result = tui_helpers._filter_vault_credentials(creds, "github")
    assert len(result) == 1
    assert result[0]["service"] == "GitHub"


def test_filter_vault_credentials_numeric_query() -> None:
    creds = [
        {"id": 1, "service": "GitHub", "username": "user123", "password": "pass"},
        {"id": 2, "service": "Test", "username": "admin", "password": "pass"},
    ]
    result = tui_helpers._filter_vault_credentials(creds, "123")
    assert len(result) == 1
    assert result[0]["username"] == "user123"


def test_find_duplicate_credential_empty_list() -> None:
    result = tui._find_duplicate_credential([], "service", "user")
    assert result is None


def test_truncate_middle_edge_cases() -> None:
    assert tui_helpers._truncate_middle("hello", 10) == "hello"
    assert tui_helpers._truncate_middle("hello", 5) == "hello"
    assert tui_helpers._truncate_middle("hello world", 8) == "he...rld"
    assert tui_helpers._truncate_middle("a", 1) == "a"
    assert tui_helpers._truncate_middle("abc", 4) == "abc"
    assert tui_helpers._truncate_middle("abc", 3) == "abc"


def test_sanitize_strips_zero_width_chars() -> None:
    for cp in range(0x200B, 0x2010):  # U+200B through U+200F
        char = chr(cp)
        text = f"abc{char}def"
        result = tui_helpers._sanitize_terminal_text(text)
        assert result == "abcdef", f"U+{cp:04X} was not stripped: got {result!r}"


def test_sanitize_replaces_bidi_controls_with_question_mark() -> None:
    for cp in range(0x202A, 0x2030):  # U+202A through U+202E
        char = chr(cp)
        text = f"abc{char}def"
        result = tui_helpers._sanitize_terminal_text(text)
        assert result == "abc?def", f"U+{cp:04X} was not replaced with '?': got {result!r}"


def test_sanitize_strips_bom() -> None:
    bom = chr(0xFEFF)
    text = f"{bom}hello{bom}"
    result = tui_helpers._sanitize_terminal_text(text)
    assert result == "hello"


def test_sanitize_mixed_c0_bidi_zero_width() -> None:
    # Mix: C0 control (ESC), bidi (RLO), zero-width (ZWSP), BOM, normal text
    text = f"start\x1b{chr(0x202E)}{chr(0x200B)}{chr(0xFEFF)}end"
    result = tui_helpers._sanitize_terminal_text(text)
    assert result == "start\\e?end"


def test_sanitize_preserves_legitimate_unicode() -> None:
    # CJK
    assert tui_helpers._sanitize_terminal_text("中文测试") == "中文测试"
    # Cyrillic
    assert tui_helpers._sanitize_terminal_text("Привет") == "Привет"
    # Emoji
    assert tui_helpers._sanitize_terminal_text("🔑 secret") == "🔑 secret"
    # Mixed scripts in one string
    assert tui_helpers._sanitize_terminal_text("中文 Привет 🔑") == "中文 Привет 🔑"


def test_sanitize_service_name_with_embedded_zero_width() -> None:
    # Simulate a phishing attack: "GitHub" with zero-width chars between visible chars
    zwsp = chr(0x200B)  # zero-width space
    zwnj = chr(0x200C)  # zero-width non-joiner
    zwj = chr(0x200D)   # zero-width joiner
    malicious = f"Git{zwsp}Hub{zwnj}Lo{zwj}gin"
    result = tui_helpers._sanitize_terminal_text(malicious)
    assert result == "GitHubLogin"
    assert zwsp not in result
    assert zwnj not in result
    assert zwj not in result


def test_sanitize_existing_c0_behavior_unchanged() -> None:
    assert tui_helpers._sanitize_terminal_text("line1\nline2") == "line1\\nline2"
    assert tui_helpers._sanitize_terminal_text("tab\there") == "tab\\there"
    assert tui_helpers._sanitize_terminal_text("cr\r") == "cr\\r"
    assert tui_helpers._sanitize_terminal_text("bs\b") == "bs\\b"
    assert tui_helpers._sanitize_terminal_text("esc\x1b") == "esc\\e"
    assert tui_helpers._sanitize_terminal_text("null\x00") == "null\\x00"
    assert tui_helpers._sanitize_terminal_text("del\x7f") == "del\\x7f"


def test_coerce_index_edge_cases() -> None:
    assert tui._coerce_index("", 5, 0) == 0
    assert tui._coerce_index("abc", 5, 0) == 0
    assert tui._coerce_index("0", 5, 0) == 0
    assert tui._coerce_index("4", 5, 0) == 4
    assert tui._coerce_index("10", 5, 0) == 4
    assert tui._coerce_index("-1", 5, 0) == 0


def test_cached_focus_items_rebuilds_only_when_composition_changes(monkeypatch) -> None:
    state = tui.AppState()
    original = tui._focus_items
    calls = 0

    def counted(current_state):
        nonlocal calls
        calls += 1
        return original(current_state)

    monkeypatch.setattr(tui, "_focus_items", counted)

    first = tui._get_cached_focus_items(state)
    first.append("mutated-by-caller")
    assert "mutated-by-caller" not in tui._get_cached_focus_items(state)
    assert calls == 1

    state.mode = "words"
    tui._get_cached_focus_items(state)
    state.username_style = "random"
    tui._get_cached_focus_items(state)
    state.vault_unlocked = True
    tui._get_cached_focus_items(state)
    state.output = "generated"
    tui._get_cached_focus_items(state)

    assert calls == 5
