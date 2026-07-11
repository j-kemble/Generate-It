from __future__ import annotations

import math
from typing import TYPE_CHECKING

from . import generator

if TYPE_CHECKING:
    from .tui_state import AppState


def _sanitize_terminal_text(text: str) -> str:
    """Replace control characters with visible escaped representations.

    Prevents control-character injection from user-controlled strings
    (service, username, note, import results) reaching curses.addstr()
    unchanged.  Printable Unicode (including non-ASCII) is left alone.
    """
    result: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp == 0x0A:          # \n
            result.append("\\n")
        elif cp == 0x09:        # \t
            result.append("\\t")
        elif cp == 0x0D:        # \r
            result.append("\\r")
        elif cp == 0x08:        # \b (backspace)
            result.append("\\b")
        elif cp == 0x1B:        # ESC
            result.append("\\e")
        elif cp < 0x20:         # other C0 controls (0x00–0x1F)
            result.append(f"\\x{cp:02x}")
        elif 0x7F <= cp <= 0x9F:  # DEL (0x7F) + C1 controls (0x80–0x9F)
            result.append(f"\\x{cp:02x}")
        else:
            result.append(ch)
    return "".join(result)


def _truncate_middle(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    keep_left = (max_len - 3) // 2
    keep_right = max_len - 3 - keep_left
    return f"{text[:keep_left]}...{text[-keep_right:]}"


def _filter_vault_credentials(credentials: list[dict], query: str) -> list[dict]:
    """Filter and rank vault credentials by fuzzy score on service/username."""
    q = query.strip().lower()
    if not q:
        return list(credentials)
    ranked: list[tuple[int, str, str, dict]] = []
    for cred in credentials:
        service = str(cred.get("service", "")).lower()
        username = str(cred.get("username", "")).lower()
        combined = f"{service} {username}".strip()

        scores = [
            s
            for s in (
                _fuzzy_score(q, service),
                _fuzzy_score(q, username),
                _fuzzy_score(q, combined),
            )
            if s is not None
        ]
        if not scores:
            continue

        ranked.append((min(scores), service, username, cred))

    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in ranked]


def _find_duplicate_credential(
    credentials: list[dict],
    service: str,
    username: str,
    *,
    exclude_id: int | None = None,
) -> dict | None:
    service_key = service.strip().lower()
    username_key = username.strip().lower()
    if not service_key or not username_key:
        return None

    for cred in credentials:
        cred_id = cred.get("id")
        if exclude_id is not None and cred_id == exclude_id:
            continue
        cred_service = str(cred.get("service", "")).strip().lower()
        cred_username = str(cred.get("username", "")).strip().lower()
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
