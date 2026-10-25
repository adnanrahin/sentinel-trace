from __future__ import annotations

import re
from collections.abc import Sequence

from sentinal_trace.detectors.base import Detector, RawMatch
from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.normalization.document import NormalizedDocument

_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_SSN_LIKE = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_ACCOUNT = re.compile(r"(?i)\b(?:account[_-]?id|tenant[_-]?id|org[_-]?id)\s*[:=]\s*([A-Za-z0-9-_]{6,})\b")


class SensitiveDataDetector(Detector):
    name = "sensitive"

    def detect(self, document: NormalizedDocument) -> Sequence[RawMatch]:
        text = document.text
        matches: list[RawMatch] = []
        for found in _EMAIL.finditer(text):
            matches.append(
                RawMatch(
                    start=found.start(),
                    end=found.end(),
                    value=found.group(0),
                    category=Category.PII,
                    subtype="email",
                    severity=Severity.SEV_3,
                    confidence=Confidence.MEDIUM,
                    rule_id="pii.email",
                    risk_score=25,
                    remediation="Avoid including personal email addresses in prompts unless necessary.",
                    risk_factors=("pii",),
                )
            )
        for found in _SSN_LIKE.finditer(text):
            matches.append(
                RawMatch(
                    start=found.start(),
                    end=found.end(),
                    value=found.group(0),
                    category=Category.PII,
                    subtype="national_id_like",
                    severity=Severity.SEV_1,
                    confidence=Confidence.LOW,
                    rule_id="pii.national_id_like",
                    risk_score=60,
                    remediation="Never send national identification numbers to AI systems.",
                    suppressible=True,
                    risk_factors=("pii", "id_pattern"),
                )
            )
        for found in _ACCOUNT.finditer(text):
            matches.append(
                RawMatch(
                    start=found.start("1"),
                    end=found.end("1"),
                    value=found.group(1),
                    category=Category.IDENTIFIER,
                    subtype="account_id",
                    severity=Severity.SEV_3,
                    confidence=Confidence.MEDIUM,
                    rule_id="id.account",
                    risk_score=28,
                    remediation="Tenant and account IDs can correlate environments; minimize sharing.",
                    risk_factors=("account_metadata",),
                )
            )
        return matches
