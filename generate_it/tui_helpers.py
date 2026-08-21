from __future__ import annotations

import math
from typing import TYPE_CHECKING

from . import generator
from .identity import canonical_identity_stripped

if TYPE_CHECKING:
    from .tui_state import AppState


def _build_sanitize_translate_table() -> dict[int, str | None]:
    """Flat helper: build translate table for sanitize, reusable, no hard-coded inline loops elsewhere."""
    table: dict[int, str | None] = {}
    # Explicit escapes
    table[0x0A] = "\\n"
    table[0x09] = "\\t"
    table[0x0D] = "\\r"
    table[0x08] = "\\b"
    table[0x1B] = "\\e"
    # Remaining C0 controls 0x00-0x1F
    for cp in range(0x00, 0x20):
        if cp not in table:
            table[cp] = f"\\x{cp:02x}"
    # DEL + C1 0x7F-0x9F
    for cp in range(0x7F, 0xA0):
        table[cp] = f"\\x{cp:02x}"
    # Zero-width strip
    for cp in range(0x200B, 0x2010):
        table[cp] = None
    table[0xFEFF] = None
    # Bidi -> "?"
    for cp in range(0x202A, 0x2030):
        table[cp] = "?"
    return table


_SANITIZE_TABLE: dict[int, str | None] = _build_sanitize_translate_table()


def _sanitize_terminal_text(text: str) -> str:
    """Replace control characters with visible escaped representations — 60 fps path.

    Uses a pre-built translate table for 2B-scale streaming so data travels
    without per-char branching. Flat, reusable via _SANITIZE_TABLE.
    """
    return text.translate(_SANITIZE_TABLE)


def _truncate_middle(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    keep_left = (max_len - 3) // 2
    keep_right = max_len - 3 - keep_left
    return f"{text[:keep_left]}...{text[-keep_right:]}"


def _credential_fields_lower(cred: dict) -> tuple[str, str, str, str]:
    """Flat helper: extract lowercased fields for filtering, reusable."""
    service = str(cred.get("service", "")).lower()
    username = str(cred.get("username", "")).lower()
    url = str(cred.get("url", "")).lower()
    combined = f"{service} {username} {url}".strip()
    return service, username, url, combined


def _best_fuzzy_score(query: str, fields: tuple[str, ...]) -> int | None:
    """Flat helper: return best (lowest) fuzzy score across fields, reusable."""
    best: int | None = None
    for field in fields:
        score = _fuzzy_score(query, field)
        if score is None:
            continue
        if best is None or score < best:
            best = score
            if best == 0:
                break
    return best


def _filter_vault_credentials(
    credentials: list[dict], query: str, limit: int | None = None
) -> list[dict]:
    """Filter and rank vault credentials by fuzzy score — flat, reusable.

    Uses modular helpers for field extraction and scoring so data travels
    with minimal allocations. Optional limit uses constants, no hard-coded inline.
    """
    import heapq

    q = query.strip().lower()
    if not q:
        if limit is not None:
            return list(credentials[:limit])
        return list(credentials)
    ranked: list[tuple[int, str, str, dict]] = []
    for cred in credentials:
        service, username, url, combined = _credential_fields_lower(cred)
        best = _best_fuzzy_score(q, (service, username, url, combined))
        if best is None:
            continue
        ranked.append((best, service, username, cred))
    if limit is not None:
        if len(ranked) > limit:
            # Heap O(n log k) beats sort O(n log n) when k << n (typical for 10k+ vaults)
            ranked = heapq.nsmallest(limit, ranked, key=lambda item: (item[0], item[1], item[2]))
            ranked.sort(key=lambda item: (item[0], item[1], item[2]))
        else:
            ranked.sort(key=lambda item: (item[0], item[1], item[2]))
        return [item[3] for item in ranked[:limit]]
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in ranked]


def _find_duplicate_credential(
    credentials: list[dict],
    service: str,
    username: str,
    *,
    exclude_id: int | None = None,
) -> dict | None:
    """Scan *credentials* for a canonical-identity match.

    Uses the single canonical identity rule (see generate_it/identity.py).
    The storage layer's ``find_credential_by_identity`` (indexed lookup) is
    preferred for interactive duplicate checks; this helper remains for
    in-memory lists and tests.
    """
    service_key = canonical_identity_stripped(service)
    username_key = canonical_identity_stripped(username)
    if not service_key or not username_key:
        return None

    for cred in credentials:
        cred_id = cred.get("id")
        if exclude_id is not None and cred_id == exclude_id:
            continue
        cred_service = canonical_identity_stripped(str(cred.get("service", "")))
        cred_username = canonical_identity_stripped(str(cred.get("username", "")))
        if cred_service == service_key and cred_username == username_key:
            return cred

    return None


def _fuzzy_score(query: str, text: str) -> int | None:
    q = query.strip().lower()
    if not q:
        return 0
    t = text.lower()

    if q in t:
        return t.index(q) * 2 + (len(t) - len(q))

    q_idx = 0
    gap_penalty = 0
    last_match = -1
    for i, ch in enumerate(t):
        if q_idx >= len(q):
            break
        if ch == q[q_idx]:
            if last_match != -1:
                gap_penalty += i - last_match - 1
            last_match = i
            q_idx += 1
    if q_idx != len(q):
        return None

    return 1000 + gap_penalty + len(t)


def _estimate_entropy_bits(state: "AppState", wordlist_size: int) -> float:
    if state.mode == "chars":
        alphabet = 0
        if state.use_letters:
            alphabet += len(generator.LETTERS)
        if state.use_numbers:
            alphabet += len(generator.NUMBERS)
        if state.use_special:
            alphabet += len(generator.SPECIAL_CHARACTERS)
        if alphabet <= 1:
            return 0.0
        return float(state.char_length) * math.log2(alphabet)

    if wordlist_size <= 1:
        base = 0.0
    else:
        base = float(state.word_count) * math.log2(wordlist_size)

    # Extra tokens are inserted into words; we show an approximate addition.
    extra = 0.0
    if state.add_numbers:
        # Digits length chosen randomly from {2,3,4}; approximate with 3 digits.
        extra += 3.0 * math.log2(10)
    if state.add_special:
        extra += math.log2(max(2, len(generator.PASSPHRASE_SPECIALS)))

    return base + extra


def _strength_label(bits: float) -> tuple[str, str]:
    # label, kind
    if bits < 40:
        return "weak", "bad"
    if bits < 60:
        return "ok", "warn"
    if bits < 80:
        return "strong", "ok"
    return "very strong", "ok"
