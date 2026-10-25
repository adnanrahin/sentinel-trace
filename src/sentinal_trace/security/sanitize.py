from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Mapping
from typing import Any

_SECRETISH = re.compile(
    r"(AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{8,}"
    r"|xox[baprs]-[A-Za-z0-9-]{8,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
    r")",
    re.IGNORECASE,
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask_secret(value: str, category: str = "SECRET") -> str:
    if not value:
        return f"[REDACTED:{category}]"
    prefix = value[:4] if len(value) >= 4 else value[:1]
    return f"{prefix}…({len(value)} chars) [REDACTED:{category}]"


def redact_text(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace [start, end) spans with placeholders. Spans must not overlap."""
    if not spans:
        return text
    ordered = sorted(spans, key=lambda s: s[0])
    out: list[str] = []
    cursor = 0
    for start, end, placeholder in ordered:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(placeholder)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def scrub_for_log(message: str) -> str:
    return _SECRETISH.sub("[REDACTED]", message)


def fingerprint_value(value: str, key: bytes) -> str:
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:32]


def sanitize_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    blocked = {"secret", "password", "token", "authorization", "api_key", "private_key", "prompt"}
    out: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in blocked:
            out[key] = "[REDACTED]"
        elif isinstance(value, str):
            out[key] = scrub_for_log(value)
        else:
            out[key] = value
    return out
