from __future__ import annotations

from typing import Dict, Iterable, Mapping, Sequence, Tuple

IMPORT_FORMATS: tuple[str, ...] = ("auto", "generic", "bitwarden", "apple", "nordpass")
EXPORT_FORMATS: tuple[str, ...] = ("generic", "spreadsheet-safe", "bitwarden", "apple", "nordpass")

IMPORT_FORMAT_LABELS: Dict[str, str] = {
    "auto": "Auto-detect",
    "generic": "Generic/Browser CSV",
    "bitwarden": "Bitwarden",
    "apple": "Apple Passwords",
    "nordpass": "NordPass",
}

EXPORT_FORMAT_LABELS: Dict[str, str] = {
    "generic": "Generic/Browser CSV",
    "spreadsheet-safe": "Spreadsheet-Safe CSV",
    "bitwarden": "Bitwarden",
    "apple": "Apple Passwords",
    "nordpass": "NordPass",
}

_IMPORT_FORMAT_ALIASES: Dict[str, str] = {
    "auto": "auto",
    "auto_detect": "auto",
    "autodetect": "auto",
    "generic": "generic",
    "browser": "generic",
    "default": "generic",
    "bitwarden": "bitwarden",
    "bw": "bitwarden",
    "apple": "apple",
    "apple_passwords": "apple",
    "icloud": "apple",
    "icloud_keychain": "apple",
    "nordpass": "nordpass",  # nosec B105 — format name, not a credential
    "nord_pass": "nordpass",  # nosec B105 — format name, not a credential
}

_EXPORT_FORMAT_ALIASES: Dict[str, str] = {
    "generic": "generic",
    "browser": "generic",
    "default": "generic",
    "spreadsheet_safe": "spreadsheet-safe",
    "spreadsheet": "spreadsheet-safe",
    "safe": "spreadsheet-safe",
    "bitwarden": "bitwarden",
    "bw": "bitwarden",
    "apple": "apple",
    "apple_passwords": "apple",
    "icloud": "apple",
    "nordpass": "nordpass",  # nosec B105 — format name, not a credential
    "nord_pass": "nordpass",  # nosec B105 — format name, not a credential
}

_IMPORT_FIELD_ALIASES: Dict[str, Dict[str, Sequence[str]]] = {
    "generic": {
        "service": ("name", "service", "title", "full_name"),
        "username": ("username", "login", "user", "email", "login_username"),
        "password": ("password", "pass", "login_password"),
        "note": ("note", "notes"),
        "url": ("url", "login_uri", "website", "address"),
    },
    "bitwarden": {
        "service": ("name", "title", "service"),
        "username": ("login_username", "username", "login", "user"),
        "password": ("login_password", "password", "pass"),
        "note": ("notes", "note"),
        "url": ("login_uri", "url", "website"),
        "type": ("type",),
    },
    "apple": {
        "service": ("title", "name", "service"),
        "username": ("username", "login", "user", "email"),
        "password": ("password", "pass"),
        "note": ("notes", "note"),
        "url": ("url", "website", "address"),
    },
    "nordpass": {
        "service": ("name", "title", "service"),
        "username": ("username", "login", "user", "email"),
        "password": ("password", "pass"),
        "note": ("note", "notes"),
        "url": ("url", "website", "address"),
        "type": ("type",),
    },
}

_EXPORT_HEADERS: Dict[str, list[str]] = {
    "generic": ["name", "url", "username", "password", "note"],
    "spreadsheet-safe": ["name", "url", "username", "password", "note"],
    "bitwarden": [
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ],
    "apple": ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"],
    "nordpass": [
        "name",
        "url",
        "username",
        "password",
        "note",
        "cardholdername",
        "cardnumber",
        "cvc",
        "expirydate",
        "zipcode",
        "folder",
        "full_name",
        "phone_number",
        "email",
        "address1",
        "address2",
        "city",
        "country",
        "state",
        "type",
        "custom_fields",
    ],
}


def normalize_header_name(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_")


_FORMULA_TRIGGERS: frozenset[str] = frozenset({"=", "+", "-", "@", "|", "%"})


def _escape_formula(value: str) -> str:
    """Prefix values that start with formula-triggering characters with a single quote.

    Spreadsheet applications like Excel, LibreOffice, and Google Sheets interpret
    cells starting with ``=``, ``+``, ``-``, ``@``, ``|``, ``%`` as formulas
    (OWASP CSV Injection).  Prepending a single-quote escapes the cell so it
    is treated as literal text.

    Leading whitespace is stripped before checking for triggers, per OWASP.
    Tab-prefixed formulas like ``\\t+SUM`` are still caught because ``lstrip``
    removes the tab and exposes the ``+``.
    """
    stripped = value.lstrip()
    if stripped and stripped[0] in _FORMULA_TRIGGERS:
        return "'" + value
    return value


def normalize_import_format(value: str) -> str:
    key = normalize_header_name(value)
    if key not in _IMPORT_FORMAT_ALIASES:
        valid = ", ".join(IMPORT_FORMATS)
        raise ValueError(f"Unsupported import format '{value}'. Expected one of: {valid}")
    return _IMPORT_FORMAT_ALIASES[key]


def normalize_export_format(value: str) -> str:
    key = normalize_header_name(value)
    if key not in _EXPORT_FORMAT_ALIASES:
        valid = ", ".join(EXPORT_FORMATS)
        raise ValueError(f"Unsupported export format '{value}'. Expected one of: {valid}")
    return _EXPORT_FORMAT_ALIASES[key]


def detect_import_format(fieldnames: Iterable[str]) -> str:
    normalized = {
        normalized_header
        for h in fieldnames
        if h and (normalized_header := normalize_header_name(h))
    }

    if {"login_username", "login_password"}.issubset(normalized):
        return "bitwarden"

    nordpass_signature = {"cardholdername", "cardnumber", "custom_fields"}
    if nordpass_signature.issubset(normalized):
        return "nordpass"

    # Apple exports commonly use Title/URL/Username/Password and may include OTPAuth.
    if "otpauth" in normalized and {"title", "username", "password"}.issubset(normalized):
        return "apple"
    if {"title", "url", "username", "password"}.issubset(normalized):
        return "apple"

    return "generic"


def resolve_import_format(fieldnames: Iterable[str], requested_format: str = "auto") -> str:
    normalized = normalize_import_format(requested_format)
    if normalized != "auto":
        return normalized
    return detect_import_format(fieldnames)


def missing_required_headers(fieldnames: Iterable[str], *, import_format: str) -> list[str]:
    normalized_format = normalize_import_format(import_format)
    if normalized_format == "auto":
        raise ValueError("missing_required_headers() requires a resolved import format, not 'auto'.")

    normalized_headers = {
        normalized_header
        for h in fieldnames
        if h and (normalized_header := normalize_header_name(h))
    }
    aliases = _IMPORT_FIELD_ALIASES[normalized_format]
    missing: list[str] = []

    for key in ("service", "username", "password"):
        variants = aliases[key]
        if not any(normalize_header_name(v) in normalized_headers for v in variants):
            missing.append("/".join(variants))

    return missing


def get_export_headers(export_format: str) -> list[str]:
    normalized = normalize_export_format(export_format)
    return list(_EXPORT_HEADERS[normalized])


def build_export_row(
    export_format: str,
    *,
    service: str,
    username: str,
    password: str,
    note: str = "",
    url: str = "",
) -> list[str]:
    normalized = normalize_export_format(export_format)

    if normalized == "generic":
        return [
            _escape_formula(service),
            _escape_formula(url),
            _escape_formula(username),
            _escape_formula(password),
            _escape_formula(note),
        ]

    if normalized == "spreadsheet-safe":
        return [
            _escape_formula(service),
            _escape_formula(url),
            _escape_formula(username),
            _escape_formula(password),
            _escape_formula(note),
        ]

    if normalized == "bitwarden":
        return [
            "",  # folder
            "0",  # favorite
            "login",  # type
            _escape_formula(service),  # name
            _escape_formula(note),  # notes
            "",  # fields
            "0",  # reprompt
            _escape_formula(url),  # login_uri
            _escape_formula(username),  # login_username
            _escape_formula(password),  # login_password
            "",  # login_totp
        ]

    if normalized == "apple":
        return [
            _escape_formula(service),  # Title
            _escape_formula(url),  # URL
            _escape_formula(username),  # Username
            _escape_formula(password),  # Password
            _escape_formula(note),  # Notes
            "",  # OTPAuth
        ]

    # nordpass
    return [
        _escape_formula(service),  # name
        _escape_formula(url),  # url
        _escape_formula(username),  # username
        _escape_formula(password),  # password
        _escape_formula(note),  # note
        "",  # cardholdername
        "",  # cardnumber
        "",  # cvc
        "",  # expirydate
        "",  # zipcode
        "",  # folder
        "",  # full_name
        "",  # phone_number
        "",  # email
        "",  # address1
        "",  # address2
        "",  # city
        "",  # country
        "",  # state
        "password",  # type
        "",  # custom_fields
    ]


def _normalize_row_flat(row: Mapping[str, str | None]) -> Dict[str, str]:
    """Flat helper: normalize a CSV row's keys/values once, reusable."""
    return {
        normalize_header_name(k): (v or "").strip()
        for k, v in row.items()
        if k is not None
    }


def _normalized_aliases_flat(
    aliases: Mapping[str, Sequence[str]],
) -> Dict[str, tuple[str, ...]]:
    """Flat helper: pre-normalize alias keys for fast lookup, reusable."""
    return {
        field: tuple(normalize_header_name(k) for k in keys)
        for field, keys in aliases.items()
    }


def _validate_row_type_flat(
    normalized_row: Mapping[str, str],
    aliases: Mapping[str, Sequence[str]],
    normalized_format: str,
    row_num: int,
) -> str | None:
    """Flat helper: validate type field, return error or None, reusable."""
    if "type" not in aliases:
        return None
    type_value = _first_present(normalized_row, aliases["type"]).lower()
    if normalized_format == "bitwarden":
        if type_value not in ("", "login", "1"):
            return f"Row {row_num}: Unsupported item type '{type_value or 'unknown'}'"
    elif normalized_format == "nordpass":
        if type_value and type_value not in ("password", "login", "credential"):
            return f"Row {row_num}: Unsupported item type '{type_value}'"
    return None


def parse_import_row(
    row: Mapping[str, str | None],
    *,
    import_format: str,
    row_num: int,
) -> Tuple[Dict[str, str] | None, str | None]:
    normalized_format = normalize_import_format(import_format)
    if normalized_format == "auto":
        raise ValueError("parse_import_row() requires a resolved import format, not 'auto'.")
    raw_aliases = _IMPORT_FIELD_ALIASES[normalized_format]
    aliases = _normalized_aliases_flat(raw_aliases)
    normalized_row = _normalize_row_flat(row)
    err = _validate_row_type_flat(normalized_row, aliases, normalized_format, row_num)
    if err:
        return None, err
    service = _first_present(normalized_row, aliases["service"])
    username = _first_present(normalized_row, aliases["username"])
    password = _first_present(normalized_row, aliases["password"])
    note = _first_present(normalized_row, aliases.get("note", ("note", "notes")))
    url = _first_present(normalized_row, aliases.get("url", ("url", "login_uri")))
    missing = []
    if not service:
        missing.append("service/name")
    if not username:
        missing.append("username/login")
    if not password:
        missing.append("password")
    if missing:
        return None, f"Row {row_num}: Missing required field(s): {', '.join(missing)}"
    return {"service": service, "username": username, "password": password, "note": note, "url": url}, None


def extract_row_identity(
    row: Mapping[str, str | None],
    *,
    import_format: str,
) -> Tuple[str, str]:
    normalized_format = normalize_import_format(import_format)
    if normalized_format == "auto":
        raise ValueError("extract_row_identity() requires a resolved import format, not 'auto'.")
    aliases = _normalized_aliases_flat(_IMPORT_FIELD_ALIASES[normalized_format])
    normalized_row = _normalize_row_flat(row)
    service = _first_present(normalized_row, aliases["service"])
    username = _first_present(normalized_row, aliases["username"])
    return service, username


def _first_present(row: Mapping[str, str], keys: Sequence[str]) -> str:
    """Flat helper: first present key, assumes keys already normalized."""
    for key in keys:
        value = row.get(key, "")
        if value:
            return value
    return ""
