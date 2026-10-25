from __future__ import annotations

import re
from collections.abc import Sequence

from sentinal_trace.detectors.base import Detector, RawMatch
from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.normalization.document import NormalizedDocument
from sentinal_trace.security.sanitize import shannon_entropy

_PATTERNS: list[tuple[re.Pattern[str], str, Severity, Confidence, int, str]] = [
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "aws_access_key_id",
        Severity.SEV_0,
        Confidence.CONFIRMED,
        95,
        "Rotate the AWS access key and never paste it into an AI prompt.",
    ),
    (
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        "github_pat",
        Severity.SEV_0,
        Confidence.HIGH,
        92,
        "Revoke the GitHub token and create a scoped replacement.",
    ),
    (
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        "github_fine_grained_pat",
        Severity.SEV_0,
        Confidence.HIGH,
        92,
        "Revoke the GitHub fine-grained token.",
    ),
    (
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "stripe_secret_key",
        Severity.SEV_0,
        Confidence.HIGH,
        90,
        "Roll the Stripe secret key in the dashboard.",
    ),
    (
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "slack_token",
        Severity.SEV_0,
        Confidence.HIGH,
        90,
        "Revoke the Slack token.",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "jwt",
        Severity.SEV_1,
        Confidence.HIGH,
        80,
        "Treat the JWT as compromised and issue a new session.",
    ),
    (
        re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"<>]+"),
        "connection_string",
        Severity.SEV_0,
        Confidence.HIGH,
        88,
        "Rotate database credentials and use a secret manager.",
    ),
]

_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[\s,;{])(?P<key>(?:api[_-]?key|secret|password|passwd|token|auth(?:orization)?|access[_-]?key))"
    r"\s*[:=]\s*(?P<q>['\"]?)(?P<val>[^\s'\"#]{12,})(?P=q)"
)

# DATABRICKS_CLIENT_SECRET=… is missed by _ASSIGNMENT because SECRET is preceded by _.
_ENV_SECRET_KEY = r"[A-Z][A-Z0-9_]*_(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY)"
_ENV_ASSIGNMENT = re.compile(
    rf"(?i)(?:^|[\s,;{{`])(?P<key>{_ENV_SECRET_KEY})"
    r"\s*[:=]\s*(?P<q>['\"]?)(?P<val>[^\s'\"#`]{12,})(?P=q)"
)
_ENV_NAME = re.compile(rf"(?i)(?:^|[\s,;{{`])(?P<key>{_ENV_SECRET_KEY})\s*=")


def _placeholder_value(value: str) -> bool:
    compact = value.strip("`'\"")
    if compact in {"...", "****", "<redacted>", "REDACTED", "redacted"}:
        return True
    return len(compact) >= 3 and set(compact) <= {".", "*", "x", "X"}

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"[\s\S]+?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)


class CredentialDetector(Detector):
    name = "credentials"

    def detect(self, document: NormalizedDocument) -> Sequence[RawMatch]:
        text = document.text
        matches: list[RawMatch] = []
        for pattern, subtype, severity, confidence, score, remediation in _PATTERNS:
            for found in pattern.finditer(text):
                matches.append(
                    RawMatch(
                        start=found.start(),
                        end=found.end(),
                        value=found.group(0),
                        category=Category.CREDENTIAL,
                        subtype=subtype,
                        severity=severity,
                        confidence=confidence,
                        rule_id=f"cred.{subtype}",
                        risk_score=score,
                        remediation=remediation,
                        suppressible=subtype not in {"aws_access_key_id"},
                        risk_factors=("known_format",),
                    )
                )
        for found in _PRIVATE_KEY.finditer(text):
            matches.append(
                RawMatch(
                    start=found.start(),
                    end=found.end(),
                    value=found.group(0),
                    category=Category.PRIVATE_KEY,
                    subtype="pem_private_key",
                    severity=Severity.SEV_0,
                    confidence=Confidence.CONFIRMED,
                    rule_id="cred.pem_private_key",
                    risk_score=99,
                    remediation="Remove the private key immediately and rotate the corresponding public key.",
                    suppressible=False,
                    risk_factors=("private_key_material",),
                )
            )
        occupied = {(m.start, m.end) for m in matches}
        for found in _ENV_ASSIGNMENT.finditer(text):
            value = found.group("val")
            start, end = found.start("val"), found.end("val")
            if _placeholder_value(value) or any(start >= s and end <= e for s, e in occupied):
                continue
            occupied.add((start, end))
            key = found.group("key").upper()
            matches.append(
                RawMatch(
                    start=start,
                    end=end,
                    value=value,
                    category=Category.CREDENTIAL,
                    subtype="env_assigned_secret",
                    severity=Severity.SEV_0,
                    confidence=Confidence.HIGH,
                    rule_id="cred.env_assignment",
                    risk_score=88,
                    remediation="Rotate the env secret and stop pasting *_SECRET / *_TOKEN assignments into chats.",
                    risk_factors=("env_assignment", f"name:{key}"),
                )
            )
        named = {factor.split(":", 1)[1] for m in matches for factor in m.risk_factors if factor.startswith("name:")}
        for found in _ENV_NAME.finditer(text):
            key = found.group("key").upper()
            if key in named:
                continue
            start, end = found.start("key"), found.end("key")
            if any(start >= s and end <= e for s, e in occupied):
                continue
            occupied.add((start, end))
            named.add(key)
            matches.append(
                RawMatch(
                    start=start,
                    end=end,
                    value=key,
                    category=Category.CREDENTIAL,
                    subtype="env_assigned_secret",
                    severity=Severity.SEV_1,
                    confidence=Confidence.HIGH,
                    rule_id="cred.env_name",
                    risk_score=80,
                    remediation="A secret-named env var was pasted.",
                    risk_factors=("env_name", f"name:{key}"),
                )
            )
        for found in _ASSIGNMENT.finditer(text):
            value = found.group("val")
            start, end = found.start("val"), found.end("val")
            if any(start >= s and end <= e for s, e in occupied):
                continue
            entropy = shannon_entropy(value)
            if entropy < 3.5 and not any(ch.isdigit() for ch in value):
                continue
            matches.append(
                RawMatch(
                    start=start,
                    end=end,
                    value=value,
                    category=Category.CREDENTIAL,
                    subtype="assigned_secret",
                    severity=Severity.SEV_1,
                    confidence=Confidence.MEDIUM if entropy < 4.0 else Confidence.HIGH,
                    rule_id="cred.assignment",
                    risk_score=70 if entropy >= 4.0 else 55,
                    remediation="Move the secret to a vault or environment injection; do not paste it into chats.",
                    risk_factors=("assignment_context", f"entropy={entropy:.2f}"),
                )
            )
        return matches
