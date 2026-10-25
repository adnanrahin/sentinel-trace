from __future__ import annotations

from sentinal_trace.detectors.base import RawMatch
from sentinal_trace.models.enums import Category
from sentinal_trace.security.sanitize import redact_text


def placeholder_for(match: RawMatch) -> str:
    if match.category is Category.COMPOSITE:
        return ""
    label = match.subtype.upper().replace("-", "_")
    return f"[REDACTED:{label}]"


def redact_matches(text: str, matches: list[RawMatch]) -> str:
    spans = [
        (m.start, m.end, placeholder_for(m))
        for m in matches
        if m.end > m.start and m.category is not Category.COMPOSITE
    ]
    return redact_text(text, spans)
