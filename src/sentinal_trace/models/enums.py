from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    SEV_0 = "SEV-0"
    SEV_1 = "SEV-1"
    SEV_2 = "SEV-2"
    SEV_3 = "SEV-3"
    SEV_4 = "SEV-4"

    @property
    def rank(self) -> int:
        return {
            Severity.SEV_0: 0,
            Severity.SEV_1: 1,
            Severity.SEV_2: 2,
            Severity.SEV_3: 3,
            Severity.SEV_4: 4,
        }[self]


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Confidence.CONFIRMED: 0,
            Confidence.HIGH: 1,
            Confidence.MEDIUM: 2,
            Confidence.LOW: 3,
        }[self]


class Category(StrEnum):
    CREDENTIAL = "credential"
    PRIVATE_KEY = "private_key"
    NETWORK = "network"
    IDENTIFIER = "identifier"
    PII = "pii"
    INFRASTRUCTURE = "infrastructure"
    SOURCE_EXPOSURE = "source_exposure"
    COMPOSITE = "composite"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    AUDIT = "audit"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class AdapterCapability(StrEnum):
    SCAN = "scan"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"
    OBSERVE_HISTORY = "observe_history"
