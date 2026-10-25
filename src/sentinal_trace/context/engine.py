from __future__ import annotations

import re

from sentinal_trace.detectors.base import RawMatch
from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.normalization.document import NormalizedDocument

_BENIGN = re.compile(
    r"(?i)\b(example|sample|dummy|synthetic|placeholder|fake|xxx+|lorem|documentation|rfc1918)\b"
)
_INJECTION = re.compile(
    r"(?i)(?:ignore (?:all )?(?:previous|prior) (?:instructions|policy)|set action (?:to )?allow|disable (?:the )?scanner)"
)


def _window(text: str, start: int, end: int, size: int = 80) -> str:
    lo = max(0, start - size)
    hi = min(len(text), end + size)
    return text[lo:hi]


def apply_context(document: NormalizedDocument, matches: list[RawMatch]) -> list[RawMatch]:
    adjusted: list[RawMatch] = []
    injection_present = bool(_INJECTION.search(document.text))
    for match in matches:
        surrounding = _window(document.text, match.start, match.end)
        factors = list(match.risk_factors)
        severity = match.severity
        confidence = match.confidence
        score = match.risk_score
        if _BENIGN.search(surrounding) and match.category in {Category.NETWORK, Category.PII, Category.IDENTIFIER}:
            confidence = Confidence.LOW
            severity = Severity.SEV_4
            score = min(score, 15)
            factors.append("benign_documentation_context")
        if match.category is Category.CREDENTIAL and _BENIGN.search(surrounding):
            confidence = Confidence.MEDIUM if confidence is Confidence.CONFIRMED else Confidence.LOW
            factors.append("labeled_synthetic_context")
        if injection_present:
            factors.append("prompt_injection_text_ignored")
        adjusted.append(
            RawMatch(
                start=match.start,
                end=match.end,
                value=match.value,
                category=match.category,
                subtype=match.subtype,
                severity=severity,
                confidence=confidence,
                rule_id=match.rule_id,
                rule_version=match.rule_version,
                remediation=match.remediation,
                suppressible=match.suppressible,
                risk_score=score,
                risk_factors=tuple(factors),
            )
        )
    return correlate(adjusted)


def correlate(matches: list[RawMatch]) -> list[RawMatch]:
    has_key = any(m.category is Category.PRIVATE_KEY or m.subtype in {"aws_access_key_id"} for m in matches)
    has_endpoint = any(m.category is Category.NETWORK for m in matches)
    extra: list[RawMatch] = []
    if has_key and has_endpoint:
        extra.append(
            RawMatch(
                start=0,
                end=0,
                value="",
                category=Category.COMPOSITE,
                subtype="credential_plus_endpoint",
                severity=Severity.SEV_0,
                confidence=Confidence.HIGH,
                rule_id="composite.cred_endpoint",
                risk_score=96,
                remediation="Credential material plus an endpoint is a high-risk composite exposure.",
                suppressible=False,
                risk_factors=("composite", "credential", "network"),
            )
        )
    return matches + extra
