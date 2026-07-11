#!/usr/bin/env python3
"""Validate issue/comment content for prompt injection patterns.

This is a regex-based first line of defense. It is not perfect — it catches
the most common and obvious injection patterns. It should be combined with
structural defenses (no write token, deterministic plan validation) for a
defense-in-depth approach.

Reads environment variables:
    ISSUE_TITLE:  The issue title (optional)
    ISSUE_BODY:   The issue body (optional)
    COMMENT_BODY: The comment body (optional)

Exit codes:
    0: Content passes validation (no injection detected)
    1: Content rejected (injection patterns found)
"""

import os
import re
import sys
from typing import List, Tuple


# ── Pattern definitions ──────────────────────────────────────────────────────

# Each tuple is (pattern_name, regex, case_sensitive)
# Patterns are designed to catch common prompt injection attempts while
# minimizing false positives on legitimate issue text.

INJECTION_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Role/system redefinition attempts
    (
        "role_redefinition",
        re.compile(
            r"(?:you\s+(?:are|act\s+as)\s+(?:now\s+)?(?:an?\s+)?"
            r"(?:d(?:eveloper|an)|hacker|attacker|exploit|malware|"
            r"unrestricted|uncensored|evil|malicious|"
            r"without\s+(?:restrictions?|limitations?|rules?|ethics?))|"
            r"pretend\s+(?:you\s+)?(?:are|to\s+be)|"
            r"role\s*(?:-|—|:)\s*(?:play\s*)?(?:system|developer|admin|"
            r"unrestricted|attacker))",
            re.IGNORECASE,
        ),
    ),
    # System prompt / instruction manipulation
    (
        "system_prompt_manipulation",
        re.compile(
            r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|"
            r"before|the\s+above)\s+(?:instructions?|messages?|"
            r"prompts?|conversation|directives?|rules?|commands?|"
            r"context)|"
            r"forget\s+(?:everything\s+)?(?:above|before|previous|"
            r"all\s+instructions?|your\s+(?:instructions?|prompt|"
            r"training))|"
            r"disregard\s+(?:all\s+)?(?:previous|prior|above|"
            r"earlier|before)\s+(?:instructions?|messages?|prompts?|"
            r"directives?))",
            re.IGNORECASE,
        ),
    ),
    # New/override instructions
    (
        "instruction_override",
        re.compile(
            r"(?:new\s+(?:system\s+)?(?:instructions?|prompts?|directives?|"
            r"rules?)\s*(?:are|is|:)|"
            r"(?:instead|now)\s+(?:follow\s+|obey\s+|listen\s+to\s+|"
            r"execute\s+|run\s+)(?:these|my|the\s+following|new)\s+"
            r"(?:instructions?|commands?|directives?|orders?)|"
            r"override\s+(?:your|the)\s+(?:instructions?|prompts?|"
            r"programming|system|rules?|directives?))",
            re.IGNORECASE,
        ),
    ),
    # Token/credential exfiltration attempts
    (
        "token_exfiltration",
        re.compile(
            r"(?:\$(?:GITHUB_TOKEN|TOKEN|SECRET|API_KEY|"
            r"GH_TOKEN|PAT|ACCESS_TOKEN|"
            r"GITHUB_[A-Z_]+|GCP_[A-Z_]+|GOOGLE_[A-Z_]+))"
            r"|(?:(?:print|echo|output|display|show|reveal|"
            r"tell\s+me|what\s+is|send|expose|leak)\s+"
            r"(?:your|the)\s+"
            r"(?:token|api\s*key|secret|credential|password|key|"
            r"\w*token\b))",
            re.IGNORECASE,
        ),
    ),
    # Data exfiltration via shell/network
    (
        "data_exfiltration",
        re.compile(
            r"(?:curl|wget|netcat|nc|telnet|ssh|scp)\s+.*"
            r"(?:\${\w+}|\$\w+|http|\.com|\.net|\.io|webhook|exfil|"
            r"send|post|upload)"
            r"|(?:base64\s*(?:-d|--decode|encode|--encode))"
            r"|(?:eval|exec|system|subprocess|os\.system)\s*\(",
            re.IGNORECASE,
        ),
    ),
    # DAN / jailbreak patterns
    (
        "jailbreak_patterns",
        re.compile(
            r"(?:\bDAN\b(?:\s*mode|\s*prompt|\s*jailbreak)?|"
            r"jailbreak|"
            r"developer\s*mode|"
            r"do\s+anything\s+now|"
            r"no\s+restrictions?\s*(?:from\s+now\s+on|anymore)|"
            r"(?:from\s+now\s+on|starting\s+now)\s+you\s+(?:have|will|"
            r"can)\s+no\s+(?:restrictions?|limitations?|rules?|"
            r"filters?|constraints?))",
            re.IGNORECASE,
        ),
    ),
    # Embedded commands in natural language (common injection vector)
    (
        "embedded_commands",
        re.compile(
            r"(?:instead\s+(?:of\s+that\s*)?(?:run|execute|do|"
            r"perform|carry\s+out)|"
            r"your\s+(?:only|new|real)\s+(?:task|job|goal|purpose|"
            r"objective|mission)\s+(?:is|now|from\s+now\s+on)\s+(?:to|"
            r"is\s+to))",
            re.IGNORECASE,
        ),
    ),
    # Base64 encoded payload (heuristic: long base64-like strings)
    (
        "base64_payload",
        re.compile(
            r"[A-Za-z0-9+/]{80,}={0,2}",
        ),
    ),
    # Suspicious URL patterns
    (
        "suspicious_urls",
        re.compile(
            r"https?://[^\s]*(?:webhook|exfil|steal|"
            r"requestbin|burpcollab|interact\.sh|"
            r"canarytokens|pipedream|hookbin|"
            r"ngrok\.io)",
            re.IGNORECASE,
        ),
    ),
]

# Patterns that are less reliable but worth flagging at lower severity
WARNING_PATTERNS: List[Tuple[str, re.Pattern]] = [
    (
        "instruction_questioning",
        re.compile(
            r"(?:what\s+(?:are|were|is)\s+(?:your|the)\s+(?:system\s+)?"
            r"(?:instructions?|prompts?|directives?|rules?|system|"
            r"initial\s+message))",
            re.IGNORECASE,
        ),
    ),
    (
        "verbose_directive",
        re.compile(
            r"(?:important|critical|essential|mandatory|must\s+follow)"
            r"\s*:\s*",
            re.IGNORECASE,
        ),
    ),
]


def get_content() -> str:
    """Collect all content from environment variables."""
    parts = []
    for var in ("ISSUE_TITLE", "ISSUE_BODY", "COMMENT_BODY"):
        val = os.environ.get(var, "")
        if val:
            parts.append(val)
    return "\n".join(parts)


def scan_patterns(
    content: str,
    patterns: List[Tuple[str, re.Pattern]],
    severity: str = "ERROR",
) -> List[str]:
    """Scan content against a list of patterns.

    Returns a list of human-readable findings.
    """
    findings: List[str] = []
    for name, pattern in patterns:
        matches = pattern.findall(content)
        if matches:
            # Extract snippets (first 3 matches, truncated)
            snippets = []
            for m in matches[:3]:
                snippet = m if isinstance(m, str) else str(m)
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                snippets.append(snippet)

            finding = (
                f"[{severity}] {name}: matched pattern "
                f"(e.g., {snippets[0]!r})"
            )
            if len(matches) > 1:
                finding += f" ({len(matches)} total matches)"
            findings.append(finding)

    return findings


def main() -> int:
    content = get_content()

    if not content.strip():
        # No content to validate — this is unusual but not a security issue
        print("validate_issue_content: no content to validate (all inputs empty)")
        return 0

    error_findings = scan_patterns(content, INJECTION_PATTERNS, "ERROR")
    warn_findings = scan_patterns(content, WARNING_PATTERNS, "WARNING")

    if error_findings:
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  PROMPT INJECTION DETECTED — content rejected           ║")
        print("╠══════════════════════════════════════════════════════════╣")
        for f in error_findings:
            print(f"║  {f}")
        print("╚══════════════════════════════════════════════════════════╝")
        return 1

    if warn_findings:
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  WARNING: Suspicious patterns detected                  ║")
        print("╠══════════════════════════════════════════════════════════╣")
        for f in warn_findings:
            print(f"║  {f}")
        print("║  Content passed, but review recommended.                ║")
        print("╚══════════════════════════════════════════════════════════╝")

    print("validate_issue_content: content passed validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
