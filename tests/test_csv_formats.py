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
