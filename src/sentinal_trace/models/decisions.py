from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from sentinal_trace.models.enums import PolicyAction
from sentinal_trace.models.findings import Finding


class PreflightDecision(BaseModel):
    """Explicit send/block decision. A blocked result never carries an approved payload."""

    allowed: bool
    verdict: PolicyAction
    content_changed: bool = False
    payload: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    reason: str
    policy_version: str
    rule_set_version: str = "1"
    adapter: str = "preflight"
    incident_id: str | None = None

    @model_validator(mode="after")
    def blocked_cannot_approve(self) -> PreflightDecision:
        blocking = self.verdict in {PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL}
        if blocking:
            if self.allowed:
                raise ValueError("blocked preflight cannot set allowed=True")
            if self.payload is not None:
                raise ValueError("blocked preflight must not return a sendable payload")
        if self.allowed and self.payload is None:
            raise ValueError("allowed preflight must include a payload")
        return self
