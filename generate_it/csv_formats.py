from __future__ import annotations

from typing import Dict, Iterable, Mapping, Sequence, Tuple

IMPORT_FORMATS: tuple[str, ...] = ("auto", "generic", "bitwarden", "apple", "nordpass")
EXPORT_FORMATS: tuple[str, ...] = ("generic", "bitwarden", "apple", "nordpass")

IMPORT_FORMAT_LABELS: Dict[str, str] = {
    "auto": "Auto-detect",
    "generic": "Generic/Browser CSV",
    "bitwarden": "Bitwarden",
    "apple": "Apple Passwords",
    "nordpass": "NordPass",
}

EXPORT_FORMAT_LABELS: Dict[str, str] = {
    "generic": "Generic/Browser CSV",
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
    "nordpass": "nordpass",
    "nord_pass": "nordpass",
}

_EXPORT_FORMAT_ALIASES: Dict[str, str] = {
    "generic": "generic",
    "browser": "generic",
    "default": "generic",
    "bitwarden": "bitwarden",
    "bw": "bitwarden",
    "apple": "apple",
    "apple_passwords": "apple",
    "icloud": "apple",
    "nordpass": "nordpass",
    "nord_pass": "nordpass",
}

_IMPORT_FIELD_ALIASES: Dict[str, Dict[str, Sequence[str]]] = {
    "generic": {
        "service": ("name", "service", "title", "full_name"),
        "username": ("username", "login", "user", "email", "login_username"),
        "password": ("password", "pass", "login_password"),
        "note": ("note", "notes"),
    },
    "bitwarden": {
        "service": ("name", "title", "service"),
        "username": ("login_username", "username", "login", "user"),
        "password": ("login_password", "password", "pass"),
        "note": ("notes", "note"),
        "type": ("type",),
    },
    "apple": {
        "service": ("title", "name", "service"),
        "username": ("username", "login", "user", "email"),
        "password": ("password", "pass"),
        "note": ("notes", "note"),
    },
    "nordpass": {
        "service": ("name", "title", "service"),
        "username": ("username", "login", "user", "email"),
        "password": ("password", "pass"),
        "note": ("note", "notes"),
        "type": ("type",),
    },
}

_EXPORT_HEADERS: Dict[str, list[str]] = {
    "generic": ["name", "url", "username", "password", "note"],
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
) -> list[str]:
    normalized = normalize_export_format(export_format)

    if normalized == "generic":
        return [service, "", username, password, note]

    if normalized == "bitwarden":
        return [
            "",  # folder
            "0",  # favorite
            "login",  # type
            service,  # name
            note,  # notes
            "",  # fields
            "0",  # reprompt
            "",  # login_uri
            username,  # login_username
            password,  # login_password
            "",  # login_totp
        ]

    if normalized == "apple":
        return [
            service,  # Title
            "",  # URL
            username,  # Username
            password,  # Password
            note,  # Notes
            "",  # OTPAuth
        ]

    # nordpass
    return [
        service,  # name
        "",  # url
        username,  # username
        password,  # password
        note,  # note
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


def parse_import_row(
    row: Mapping[str, str | None],
    *,
    import_format: str,
    row_num: int,
) -> Tuple[Dict[str, str] | None, str | None]:
    normalized_format = normalize_import_format(import_format)
    if normalized_format == "auto":
        raise ValueError("parse_import_row() requires a resolved import format, not 'auto'.")

    aliases = _IMPORT_FIELD_ALIASES[normalized_format]
    normalized_row = {
        normalize_header_name(k): (v or "").strip()
        for k, v in row.items()
        if k is not None
    }

    if "type" in aliases:
        type_value = _first_present(normalized_row, aliases["type"]).lower()
        if normalized_format == "bitwarden":
            if type_value not in ("", "login", "1"):
                return None, f"Row {row_num}: Unsupported item type '{type_value or 'unknown'}'"
        elif normalized_format == "nordpass":
            if type_value and type_value not in ("password", "login", "credential"):
                return None, f"Row {row_num}: Unsupported item type '{type_value}'"

    service = _first_present(normalized_row, aliases["service"])
    username = _first_present(normalized_row, aliases["username"])
    password = _first_present(normalized_row, aliases["password"])
    note = _first_present(normalized_row, aliases.get("note", ("note", "notes")))

    missing = []
    if not service:
        missing.append("service/name")
    if not username:
        missing.append("username/login")
    if not password:
        missing.append("password")

    if missing:
        return None, f"Row {row_num}: Missing required field(s): {', '.join(missing)}"

    return {"service": service, "username": username, "password": password, "note": note}, None

def extract_row_identity(
    row: Mapping[str, str | None],
    *,
    import_format: str,
) -> Tuple[str, str]:
    normalized_format = normalize_import_format(import_format)
    if normalized_format == "auto":
        raise ValueError("extract_row_identity() requires a resolved import format, not 'auto'.")

    aliases = _IMPORT_FIELD_ALIASES[normalized_format]
    normalized_row = {
        normalize_header_name(k): (v or "").strip()
        for k, v in row.items()
        if k is not None
    }
    service = _first_present(normalized_row, aliases["service"])
    username = _first_present(normalized_row, aliases["username"])
    return service, username


def _first_present(row: Mapping[str, str], keys: Sequence[str]) -> str:
    for key in keys:
        normalized_key = normalize_header_name(key)
        value = row.get(normalized_key, "")
        if value:
            return value
    return ""
