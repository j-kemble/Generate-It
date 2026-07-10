from __future__ import annotations

import pytest

from generate_it import csv_formats


def test_normalize_format_aliases() -> None:
    assert csv_formats.normalize_import_format("auto_detect") == "auto"
    assert csv_formats.normalize_import_format("bw") == "bitwarden"
    assert csv_formats.normalize_import_format("nord_pass") == "nordpass"

    assert csv_formats.normalize_export_format("browser") == "generic"
    assert csv_formats.normalize_export_format("apple_passwords") == "apple"


def test_normalize_format_invalid_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported import format"):
        csv_formats.normalize_import_format("invalid-format")

    with pytest.raises(ValueError, match="Unsupported export format"):
        csv_formats.normalize_export_format("invalid-format")


def test_detect_import_format_variants() -> None:
    assert (
        csv_formats.detect_import_format(
            ["folder", "type", "name", "login_username", "login_password"]
        )
        == "bitwarden"
    )
    assert (
        csv_formats.detect_import_format(["name", "cardholdername", "cardnumber", "custom_fields"])
        == "nordpass"
    )
    assert csv_formats.detect_import_format(["Title", "URL", "Username", "Password"]) == "apple"
    assert csv_formats.detect_import_format(["title", "username", "password", "otpauth"]) == "apple"
    assert csv_formats.detect_import_format(["name", "username", "password"]) == "generic"


def test_resolve_import_format_respects_explicit_choice() -> None:
    # Even with Bitwarden-like headers, explicit format should win.
    fieldnames = ["name", "login_username", "login_password", "type"]
    assert csv_formats.resolve_import_format(fieldnames, requested_format="generic") == "generic"


def test_missing_required_headers_behaviour() -> None:
    with pytest.raises(ValueError, match="requires a resolved import format"):
        csv_formats.missing_required_headers(["name", "username", "password"], import_format="auto")

    # For bitwarden we require login_username + login_password + name variants.
    missing = csv_formats.missing_required_headers(
        ["name", "login_username"],
        import_format="bitwarden",
    )
    assert any("login_password" in item for item in missing)


def test_parse_import_row_rejects_auto_format() -> None:
    with pytest.raises(ValueError, match="requires a resolved import format"):
        csv_formats.parse_import_row(
            {"name": "GitHub", "username": "dev", "password": "pw"},
            import_format="auto",
            row_num=2,
        )


def test_parse_import_row_bitwarden_type_handling() -> None:
    parsed, issue = csv_formats.parse_import_row(
        {
            "type": "1",
            "name": "GitHub",
            "login_username": "dev",
            "login_password": "pw",
        },
        import_format="bitwarden",
        row_num=2,
    )
    assert issue is None
    assert parsed == {"service": "GitHub", "username": "dev", "password": "pw", "note": ""}

    parsed, issue = csv_formats.parse_import_row(
        {
            "type": "card",
            "name": "Visa",
            "login_username": "ignored",
            "login_password": "ignored",
        },
        import_format="bitwarden",
        row_num=4,
    )
    assert parsed is None
    assert issue == "Row 4: Unsupported item type 'card'"


def test_parse_import_row_missing_fields_reports_issue() -> None:
    parsed, issue = csv_formats.parse_import_row(
        {
            "name": "GitHub",
            "username": "",
            "password": "",
        },
        import_format="generic",
        row_num=3,
    )
    assert parsed is None
    assert "Missing required field(s)" in issue


def test_extract_row_identity() -> None:
    with pytest.raises(ValueError, match="requires a resolved import format"):
        csv_formats.extract_row_identity(
            {"name": "GitHub", "username": "dev"},
            import_format="auto",
        )

    service, username = csv_formats.extract_row_identity(
        {"name": "GitHub", "username": "dev"},
        import_format="generic",
    )
    assert service == "GitHub"
    assert username == "dev"


def test_normalize_header_name() -> None:
    assert csv_formats.normalize_header_name("User Name") == "user_name"
    assert csv_formats.normalize_header_name("PASSWORD") == "password"
    assert csv_formats.normalize_header_name("URL") == "url"
    assert csv_formats.normalize_header_name("notes") == "notes"
    assert csv_formats.normalize_header_name("custom_field") == "custom_field"
    assert csv_formats.normalize_header_name("login_username") == "login_username"


def test_get_export_headers() -> None:
    generic_headers = csv_formats.get_export_headers("generic")
    assert "name" in generic_headers
    assert "username" in generic_headers
    assert "password" in generic_headers
    assert "note" in generic_headers
    
    bitwarden_headers = csv_formats.get_export_headers("bitwarden")
    assert "name" in bitwarden_headers
    assert "login_username" in bitwarden_headers
    assert "login_password" in bitwarden_headers
    
    apple_headers = csv_formats.get_export_headers("apple")
    assert "Title" in apple_headers
    assert "Username" in apple_headers
    
    nordpass_headers = csv_formats.get_export_headers("nordpass")
    assert "name" in nordpass_headers
    assert "username" in nordpass_headers


def test_build_export_row() -> None:
    row = csv_formats.build_export_row(
        "generic",
        service="GitHub",
        username="dev@example.com",
        password="secret123",
        note="My note",
    )
    assert row[0] == "GitHub"
    assert row[3] == "secret123"
    assert row[4] == "My note"
    
    bw_row = csv_formats.build_export_row(
        "bitwarden",
        service="GitHub",
        username="dev@example.com",
        password="secret123",
        note="Test note",
    )
    assert "GitHub" in bw_row
    assert "dev@example.com" in bw_row
    assert "secret123" in bw_row


def test_build_export_row_without_note() -> None:
    row = csv_formats.build_export_row(
        "generic",
        service="GitHub",
        username="dev",
        password="pass",
    )
    assert row[4] == ""


def test_parse_import_row_all_formats() -> None:
    parsed, issue = csv_formats.parse_import_row(
        {"name": "Test", "username": "user", "password": "pass", "note": "test note"},
        import_format="generic",
        row_num=1,
    )
    assert parsed is not None
    assert parsed["note"] == "test note"
    
    parsed, issue = csv_formats.parse_import_row(
        {"title": "Test", "username": "user", "password": "pass"},
        import_format="apple",
        row_num=1,
    )
    assert parsed is not None
    assert parsed["service"] == "Test"
    
    parsed, issue = csv_formats.parse_import_row(
        {"name": "Test", "username": "user", "password": "pass", "notes": "nordpass note"},
        import_format="nordpass",
        row_num=1,
    )
    assert parsed is not None
    assert "nordpass note" in parsed["note"]


def test_detect_import_format_edge_cases() -> None:
    assert csv_formats.detect_import_format(["login_username", "login_password", "name"]) == "bitwarden"
    assert csv_formats.detect_import_format(["password", "username"]) == "generic"
    assert csv_formats.detect_import_format(["url", "username", "password", "note"]) == "generic"


def test_detect_import_format_normalizes_each_nonempty_header_once(monkeypatch) -> None:
    calls: list[str] = []
    original = csv_formats.normalize_header_name

    def counted(value: str) -> str:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(csv_formats, "normalize_header_name", counted)

    assert csv_formats.detect_import_format(
        [" Name ", "", "login username", "login-password"]
    ) == "bitwarden"
    assert calls == [" Name ", "login username", "login-password"]


def test_missing_required_headers_normalizes_each_supplied_header_once(monkeypatch) -> None:
    calls: list[str] = []
    original = csv_formats.normalize_header_name

    def counted(value: str) -> str:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(csv_formats, "normalize_header_name", counted)
    headers = [" Name ", "User Name", " Pass Word ", ""]

    csv_formats.missing_required_headers(headers, import_format="generic")

    assert all(calls.count(header) == 1 for header in headers[:-1])
