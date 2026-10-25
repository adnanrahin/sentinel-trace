from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.models.findings import Finding, SourceLocation
from sentinal_trace.normalization.document import NormalizedDocument
from sentinal_trace.security.sanitize import mask_secret


@dataclass(frozen=True)
class RawMatch:
    start: int
    end: int
    value: str
    category: Category
    subtype: str
    severity: Severity
    confidence: Confidence
    rule_id: str
    rule_version: str = "1"
    remediation: str = "Remove or replace the sensitive value before sending."
    suppressible: bool = True
    risk_score: int = 50
    risk_factors: tuple[str, ...] = ()


def line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index + 1 if last_nl < 0 else index - last_nl
    return line, col


def to_finding(match: RawMatch, document: NormalizedDocument, finding_id: str) -> Finding:
    line, col = line_col(document.text, match.start)
    end_line, end_col = line_col(document.text, max(match.start, match.end - 1))
    return Finding(
        finding_id=finding_id,
        category=match.category,
        subtype=match.subtype,
        severity=match.severity,
        confidence=match.confidence,
        location=SourceLocation(
            path=document.path,
            line_start=line,
            line_end=end_line,
            column_start=col,
            column_end=end_col,
        ),
        sanitized_evidence=mask_secret(match.value, match.subtype.upper()),
        rule_id=match.rule_id,
        rule_version=match.rule_version,
        risk_factors=list(match.risk_factors),
        remediation=match.remediation,
        suppressible=match.suppressible,
        risk_score=match.risk_score,
    )


class Detector:
    name: str = "base"

    def detect(self, document: NormalizedDocument) -> Sequence[RawMatch]:
        raise NotImplementedError
