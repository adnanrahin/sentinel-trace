from __future__ import annotations

from pydantic import BaseModel, Field

from sentinal_trace.models.enums import Category, Confidence, PolicyAction, Severity


class SourceLocation(BaseModel):
    path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None


class Finding(BaseModel):
    finding_id: str
    category: Category
    subtype: str
    severity: Severity
    confidence: Confidence
    location: SourceLocation = Field(default_factory=SourceLocation)
    sanitized_evidence: str
    rule_id: str
    rule_version: str = "1"
    risk_factors: list[str] = Field(default_factory=list)
    remediation: str
    suppressible: bool = True
    risk_score: int = Field(ge=0, le=100, default=50)
    fingerprint: str | None = None


class ScanLimits(BaseModel):
    truncated: bool = False
    bytes_scanned: int = 0
    max_bytes: int = 0
    errors: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    adapter: str
    source: str
    limits: ScanLimits = Field(default_factory=ScanLimits)
    policy_action: PolicyAction | None = None
    policy_version: str | None = None
    rule_set_version: str = "1"

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: f.severity.rank).severity
