from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from sentinal_trace.models.enums import Category, Confidence, PolicyAction, Severity
from sentinal_trace.models.findings import Finding, ScanResult

DEFAULT_POLICY_YAML = """
version: "1"
default_action: allow
rules:
  - id: block-confirmed-credentials
    match:
      categories: [credential, private_key, composite]
      min_severity: SEV-1
      min_confidence: high
    action: block
  - id: redact-medium-credentials
    match:
      categories: [credential]
      min_severity: SEV-2
    action: redact
  - id: warn-infrastructure
    match:
      categories: [infrastructure]
    action: warn
  - id: warn-internal-network
    match:
      categories: [network]
      min_severity: SEV-3
    action: warn
  - id: audit-pii
    match:
      categories: [pii, identifier]
    action: audit
notify_on: [block, redact]
exceptions:
  - id: synthetic-fixtures
    path_glob: "**/tests/fixtures/**"
    reason: "Labeled synthetic test fixtures"
    action: audit
"""


class RuleMatch(BaseModel):
    categories: list[Category] | None = None
    subtypes: list[str] | None = None
    min_severity: Severity | None = None
    min_confidence: Confidence | None = None


class PolicyRule(BaseModel):
    id: str
    match: RuleMatch = Field(default_factory=RuleMatch)
    action: PolicyAction
    reason: str | None = None


class PolicyException(BaseModel):
    id: str
    path_glob: str | None = None
    reason: str
    action: PolicyAction = PolicyAction.AUDIT


class PolicyConfig(BaseModel):
    version: str = "1"
    default_action: PolicyAction = PolicyAction.ALLOW
    rules: list[PolicyRule] = Field(default_factory=list)
    exceptions: list[PolicyException] = Field(default_factory=list)
    notify_on: list[PolicyAction] = Field(default_factory=lambda: [PolicyAction.BLOCK, PolicyAction.REDACT])


_ACTION_RANK = {
    PolicyAction.ALLOW: 0,
    PolicyAction.AUDIT: 1,
    PolicyAction.WARN: 2,
    PolicyAction.REDACT: 3,
    PolicyAction.REQUIRE_APPROVAL: 4,
    PolicyAction.BLOCK: 5,
}


def load_policy(path: Path | None = None) -> PolicyConfig:
    if path is None or not path.exists():
        data = yaml.safe_load(DEFAULT_POLICY_YAML)
        return PolicyConfig.model_validate(data)
    loaded: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return PolicyConfig.model_validate(loaded)


def _finding_matches(finding: Finding, rule: PolicyRule) -> bool:
    spec = rule.match
    if spec.categories and finding.category not in spec.categories:
        return False
    if spec.subtypes and finding.subtype not in spec.subtypes:
        return False
    if spec.min_severity and finding.severity.rank > spec.min_severity.rank:
        return False
    if spec.min_confidence and finding.confidence.rank > spec.min_confidence.rank:
        return False
    return True


def _exception_applies(result: ScanResult, exception: PolicyException) -> bool:
    if not exception.path_glob or not result.source:
        return False
    from fnmatch import fnmatch

    return fnmatch(result.source.replace("\\", "/"), exception.path_glob.replace("\\", "/"))


def evaluate_policy(result: ScanResult, policy: PolicyConfig) -> PolicyAction:
    for exception in policy.exceptions:
        if _exception_applies(result, exception):
            result.policy_action = exception.action
            result.policy_version = policy.version
            return exception.action

    chosen = policy.default_action
    if not result.findings:
        result.policy_action = chosen
        result.policy_version = policy.version
        return chosen

    for finding in result.findings:
        for rule in policy.rules:
            if _finding_matches(finding, rule) and _ACTION_RANK[rule.action] > _ACTION_RANK[chosen]:
                chosen = rule.action
    result.policy_action = chosen
    result.policy_version = policy.version
    return chosen
