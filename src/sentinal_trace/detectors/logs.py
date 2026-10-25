from __future__ import annotations

import re
from collections.abc import Sequence

from sentinal_trace.detectors.base import Detector, RawMatch
from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.normalization.document import NormalizedDocument

_BEARER = re.compile(r"(?i)(?:authorization|auth):\s*bearer\s+(\S+)")
_API_HEADER = re.compile(r"(?i)(?:x-api-key|api-key|x-amz-security-token):\s*(\S+)")
_COOKIE = re.compile(r"(?i)(?:set-cookie|cookie):\s*([^\r\n]{12,})")
_AWS_SECRET = re.compile(
    r'(?i)(?:aws_secret_access_key|secretaccesskey|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{30,})["\']?'
)
_BASIC = re.compile(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})")


class LogLeakDetector(Detector):
    """Catch credentials that show up in pasted logs, dumps, and HTTP traces."""

    name = "logs"

    def detect(self, document: NormalizedDocument) -> Sequence[RawMatch]:
        text = document.text
        matches: list[RawMatch] = []
        specs = (
            (
                _BEARER,
                "bearer_token",
                Severity.SEV_0,
                Confidence.HIGH,
                93,
                "Revoke the bearer token; do not paste Authorization headers.",
            ),
            (
                _API_HEADER,
                "api_header",
                Severity.SEV_0,
                Confidence.HIGH,
                90,
                "Rotate the API key that appeared in the log header.",
            ),
            (
                _COOKIE,
                "session_cookie",
                Severity.SEV_1,
                Confidence.MEDIUM,
                72,
                "Invalidate the session cookie leaked in the log.",
            ),
            (
                _AWS_SECRET,
                "aws_secret_access_key",
                Severity.SEV_0,
                Confidence.HIGH,
                94,
                "Rotate the AWS secret access key immediately.",
            ),
            (
                _BASIC,
                "basic_auth",
                Severity.SEV_0,
                Confidence.HIGH,
                91,
                "Rotate the basic-auth credential leaked in the log.",
            ),
        )
        for pattern, subtype, severity, confidence, score, remediation in specs:
            for found in pattern.finditer(text):
                value = found.group(1)
                matches.append(
                    RawMatch(
                        start=found.start(1),
                        end=found.end(1),
                        value=value,
                        category=Category.CREDENTIAL,
                        subtype=subtype,
                        severity=severity,
                        confidence=confidence,
                        rule_id=f"log.{subtype}",
                        risk_score=score,
                        remediation=remediation,
                        suppressible=False,
                        risk_factors=("log_paste", "header_or_dump"),
                    )
                )
        return matches
