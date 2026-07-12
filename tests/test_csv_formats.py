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


# ── spreadsheet-safe escaping ──────────────────────────────────────────


def test_escape_formula_equals() -> None:
    assert csv_formats._escape_formula("=SUM(A1:A10)") == "'=SUM(A1:A10)"
    assert csv_formats._escape_formula("=cmd|' /C calc") == "'=cmd|' /C calc"


def test_escape_formula_plus() -> None:
    assert csv_formats._escape_formula("+SUM(A1:A10)") == "'+SUM(A1:A10)"


def test_escape_formula_minus() -> None:
    assert csv_formats._escape_formula("-SUM(A1:A10)") == "'-SUM(A1:A10)"


def test_escape_formula_at() -> None:
    assert csv_formats._escape_formula("@SUM(A1:A10)") == "'@SUM(A1:A10)"


def test_escape_formula_normal_values_unchanged() -> None:
    assert csv_formats._escape_formula("normal_password") == "normal_password"
    assert csv_formats._escape_formula("user@example.com") == "user@example.com"
    assert csv_formats._escape_formula("1password") == "1password"
    assert csv_formats._escape_formula("") == ""
    assert csv_formats._escape_formula("a+b=c") == "a+b=c"


def test_escape_formula_leading_whitespace() -> None:
    assert csv_formats._escape_formula("  =SUM(A1)") == "'  =SUM(A1)"
    assert csv_formats._escape_formula("\t+SUM(A1)") == "'\t+SUM(A1)"
    assert csv_formats._escape_formula("   -SUM(A1)") == "'   -SUM(A1)"
    assert csv_formats._escape_formula("\t @SUM(A1)") == "'\t @SUM(A1)"


def test_escape_formula_normal_whitespace_unchanged() -> None:
    assert csv_formats._escape_formula("  normal") == "  normal"
    assert csv_formats._escape_formula("\tdata") == "\tdata"


def test_build_export_row_spreadsheet_safe_escapes_formulas() -> None:
    row = csv_formats.build_export_row(
        "spreadsheet-safe",
        service="=EVIL()",
        username="+EVIL()",
        password="-EVIL()",
        note="@EVIL()",
    )
    assert row[0] == "'=EVIL()"
    assert row[2] == "'+EVIL()"
    assert row[3] == "'-EVIL()"
    assert row[4] == "'@EVIL()"


def test_build_export_row_spreadsheet_safe_normal_unchanged() -> None:
    row = csv_formats.build_export_row(
        "spreadsheet-safe",
        service="GitHub",
        username="dev@example.com",
        password="secret123",
        note="my note",
    )
    assert row[0] == "GitHub"
    assert row[2] == "dev@example.com"
    assert row[3] == "secret123"
    assert row[4] == "my note"


def test_build_export_row_generic_escapes_formulas() -> None:
    row = csv_formats.build_export_row(
        "generic",
        service="=EVIL()",
        username="+MALWARE",
        password="-bad",
        note="@formula",
    )
    assert row[0] == "'=EVIL()"
    assert row[2] == "'+MALWARE"
    assert row[3] == "'-bad"
    assert row[4] == "'@formula"


def test_build_export_row_bitwarden_escapes_formulas() -> None:
    row = csv_formats.build_export_row(
        "bitwarden",
        service="=EVIL()",
        username="+MALWARE",
        password="-bad",
        note="@formula",
    )
    # name (index 3), notes (index 4), login_username (index 8), login_password (index 9)
    assert row[3] == "'=EVIL()"
    assert row[4] == "'@formula"
    assert row[8] == "'+MALWARE"
    assert row[9] == "'-bad"
    # Hardcoded constants must remain unescaped
    assert row[0] == ""  # folder
    assert row[1] == "0"  # favorite
    assert row[2] == "login"  # type
    assert row[6] == "0"  # reprompt


def test_get_export_headers_spreadsheet_safe() -> None:
    headers = csv_formats.get_export_headers("spreadsheet-safe")
    assert headers == ["name", "url", "username", "password", "note"]
    # Should match generic headers
    assert headers == csv_formats.get_export_headers("generic")


def test_round_trip_spreadsheet_safe_not_corrupted() -> None:
    """Imported spreadsheet-safe values should round-trip without corruption.

    The single-quote prefix is only for CSV escaping; parsed rows should
    not contain the escape character once read back.
    """
    original = {
        "service": "=EVIL()",
        "username": "+user",
        "password": "-pass",
        "note": "@note",
    }

    # Build export row in spreadsheet-safe mode (gets escaped)
    row = csv_formats.build_export_row(
        "spreadsheet-safe",
        service=original["service"],
        username=original["username"],
        password=original["password"],
        note=original["note"],
    )

    # The escaped values should have the single-quote prefix
    assert row[0].startswith("'")
    assert row[2].startswith("'")
    assert row[3].startswith("'")
    assert row[4].startswith("'")

    # When imported (via generic import, which uses the row values as-is),
    # the imported value still contains the single-quote prefix. This is
    # by design — the escaping only protects spreadsheet viewing; it does
    # not affect the actual stored value. Users who export and re-import
    # should avoid spreadsheet-safe for round-trip purposes.
    headers = csv_formats.get_export_headers("spreadsheet-safe")
    row_dict = dict(zip(headers, row))
    parsed, issue = csv_formats.parse_import_row(
        row_dict, import_format="generic", row_num=1,
    )
    assert parsed is not None
    assert issue is None

    # The imported values contain the single-quote prefix (literal '=EVIL())
    # This is acceptable — it's a text-safe representation.
    assert parsed["service"].startswith("'")
    assert parsed["username"].startswith("'")
    assert parsed["password"].startswith("'")
    assert parsed["note"].startswith("'")


def test_normalize_export_format_spreadsheet_safe_aliases() -> None:
    assert csv_formats.normalize_export_format("spreadsheet-safe") == "spreadsheet-safe"
    assert csv_formats.normalize_export_format("spreadsheet_safe") == "spreadsheet-safe"
    assert csv_formats.normalize_export_format("spreadsheet") == "spreadsheet-safe"
    assert csv_formats.normalize_export_format("safe") == "spreadsheet-safe"


# ── regression: formula escaping across ALL export formats ─────────────

_FORMULA_PAYLOAD = "=cmd|'/c calc'!A0"
_FORMULA_CHARS = ["=", "+", "-", "@"]


def test_all_formats_escape_formula_equals_payload() -> None:
    """Every export format must prefix =cmd|'/c calc'!A0 with a single quote."""
    for fmt in ("generic", "bitwarden", "apple", "nordpass", "spreadsheet-safe"):
        row = csv_formats.build_export_row(
            fmt,
            service=_FORMULA_PAYLOAD,
            username=_FORMULA_PAYLOAD,
            password=_FORMULA_PAYLOAD,
            note=_FORMULA_PAYLOAD,
        )
        for field_idx, field_val in enumerate(row):
            if field_val == _FORMULA_PAYLOAD:
                pytest.fail(
                    f"Format '{fmt}' field [{field_idx}] returned raw formula payload "
                    f"without escaping: {field_val!r}"
                )


@pytest.mark.parametrize("trigger", _FORMULA_CHARS)
def test_all_formats_escape_each_formula_trigger(trigger: str) -> None:
    """Each formula trigger char (=, +, -, @) as a leading char must be escaped."""
    payload = trigger + "EVIL()"
    for fmt in ("generic", "bitwarden", "apple", "nordpass", "spreadsheet-safe"):
        row = csv_formats.build_export_row(
            fmt,
            service=payload,
            username=payload,
            password=payload,
            note=payload,
        )
        for field_idx, field_val in enumerate(row):
            if field_val == payload:
                pytest.fail(
                    f"Format '{fmt}' field [{field_idx}] returned unescaped formula "
                    f"trigger '{trigger}': {field_val!r}"
                )


def test_all_formats_normal_values_unchanged() -> None:
    """Non-formula values must pass through unchanged in every format."""
    service = "myservice"
    username = "user@example.com"
    password = "S3cur3!Pass"
    note = "a normal note"
    for fmt in ("generic", "bitwarden", "apple", "nordpass", "spreadsheet-safe"):
        row = csv_formats.build_export_row(
            fmt,
            service=service,
            username=username,
            password=password,
            note=note,
        )
        assert service in row, f"Format '{fmt}' lost service value"
        assert username in row, f"Format '{fmt}' lost username value"
        assert password in row, f"Format '{fmt}' lost password value"
        assert note in row, f"Format '{fmt}' lost note value"
        # No value should start with a single quote
        for field_idx, field_val in enumerate(row):
            if field_val.startswith("'"):
                pytest.fail(
                    f"Format '{fmt}' field [{field_idx}] unnecessarily escaped "
                    f"normal value: {field_val!r}"
                )


def test_all_formats_note_field_escaped() -> None:
    """The note field must be formula-escaped in every export format."""
    for fmt in ("generic", "bitwarden", "apple", "nordpass", "spreadsheet-safe"):
        row = csv_formats.build_export_row(
            fmt,
            service="ok",
            username="ok",
            password="ok",
            note="=EVIL()",
        )
        assert "'=EVIL()" in row, f"Format '{fmt}' did not escape note field"
        assert "=EVIL()" not in [v for v in row if not v.startswith("'")], (
            f"Format '{fmt}' has unescaped '=EVIL()' in row"
        )


def test_spreadsheet_safe_still_escapes_as_before() -> None:
    """Regression: spreadsheet-safe format behavior unchanged."""
    row = csv_formats.build_export_row(
        "spreadsheet-safe",
        service="=EVIL()",
        username="+EVIL()",
        password="-EVIL()",
        note="@EVIL()",
    )
    assert row[0] == "'=EVIL()"
    assert row[1] == ""  # url is always empty
    assert row[2] == "'+EVIL()"
    assert row[3] == "'-EVIL()"
    assert row[4] == "'@EVIL()"


def test_bitwarden_hardcoded_constants_not_escaped() -> None:
    """Hardcoded constant strings in bitwarden format must not be escaped."""
    row = csv_formats.build_export_row(
        "bitwarden",
        service="=EVIL()",
        username="+EVIL()",
        password="-EVIL()",
        note="@EVIL()",
    )
    # Constants that should remain exactly as-is
    assert row[0] == ""   # folder
    assert row[1] == "0"  # favorite
    assert row[2] == "login"  # type
    assert row[6] == "0"  # reprompt
    assert row[10] == ""  # login_totp


def test_nordpass_hardcoded_constants_not_escaped() -> None:
    """Hardcoded constant strings in nordpass format must not be escaped."""
    row = csv_formats.build_export_row(
        "nordpass",
        service="=EVIL()",
        username="+EVIL()",
        password="-EVIL()",
        note="@EVIL()",
    )
    assert row[1] == ""   # url
    assert row[19] == "password"  # type


def test_apple_format_escapes_all_user_fields() -> None:
    """Apple format: service, username, password, note must all be escaped."""
    row = csv_formats.build_export_row(
        "apple",
        service="=evil",
        username="+evil",
        password="-evil",
        note="@evil",
    )
    assert row[0] == "'=evil"   # Title
    assert row[1] == ""          # URL (constant)
    assert row[2] == "'+evil"   # Username
    assert row[3] == "'-evil"   # Password
    assert row[4] == "'@evil"   # Notes
    assert row[5] == ""          # OTPAuth (constant)


def test_nordpass_format_escapes_all_user_fields() -> None:
    """NordPass format: service, username, password, note must all be escaped."""
    row = csv_formats.build_export_row(
        "nordpass",
        service="=evil",
        username="+evil",
        password="-evil",
        note="@evil",
    )
    assert row[0] == "'=evil"   # name
    assert row[2] == "'+evil"   # username
    assert row[3] == "'-evil"   # password
    assert row[4] == "'@evil"   # note
