from __future__ import annotations

import re
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv4Network

from sentinal_trace.detectors.base import Detector, RawMatch
from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.normalization.document import NormalizedDocument

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_INTERNAL_HOST = re.compile(
    r"\b(?:[a-z0-9-]+\.)*(?:internal|corp|lan|local|intranet)(?:\.[a-z0-9-]+)+\b",
    re.IGNORECASE,
)
_K8S = re.compile(r"(?im)^\s*kind:\s*Secret\b")
_CLOUD_ARN = re.compile(r"\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s'\"\\]+")

_PRIVATE = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),
)


class NetworkDetector(Detector):
    name = "network"

    def detect(self, document: NormalizedDocument) -> Sequence[RawMatch]:
        text = document.text
        matches: list[RawMatch] = []
        for found in _IPV4.finditer(text):
            raw = found.group(0)
            try:
                ip = IPv4Address(raw)
            except ValueError:
                continue
            if ip in IPv4Network("0.0.0.0/8") or ip in IPv4Network("255.255.255.255/32"):
                continue
            private = any(ip in net for net in _PRIVATE)
            matches.append(
                RawMatch(
                    start=found.start(),
                    end=found.end(),
                    value=raw,
                    category=Category.NETWORK,
                    subtype="private_ipv4" if private else "public_ipv4",
                    severity=Severity.SEV_3 if private else Severity.SEV_4,
                    confidence=Confidence.HIGH if private else Confidence.MEDIUM,
                    rule_id="net.ipv4",
                    risk_score=35 if private else 15,
                    remediation="Confirm whether this address reveals internal topology before sharing.",
                    risk_factors=("ip_address", "private" if private else "public"),
                )
            )
        for found in _INTERNAL_HOST.finditer(text):
            matches.append(
                RawMatch(
                    start=found.start(),
                    end=found.end(),
                    value=found.group(0),
                    category=Category.NETWORK,
                    subtype="internal_hostname",
                    severity=Severity.SEV_2,
                    confidence=Confidence.MEDIUM,
                    rule_id="net.internal_host",
                    risk_score=40,
                    remediation="Avoid sharing internal hostnames outside the trust boundary.",
                    risk_factors=("internal_dns",),
                )
            )
        found_secret = _K8S.search(text)
        if found_secret:
            matches.append(
                RawMatch(
                    start=found_secret.start(),
                    end=found_secret.end(),
                    value=found_secret.group(0),
                    category=Category.INFRASTRUCTURE,
                    subtype="kubernetes_secret",
                    severity=Severity.SEV_1,
                    confidence=Confidence.MEDIUM,
                    rule_id="infra.k8s_secret",
                    risk_score=65,
                    remediation="Do not paste Kubernetes Secret manifests into AI tools.",
                    risk_factors=("k8s_secret_manifest",),
                )
            )
        for found in _CLOUD_ARN.finditer(text):
            matches.append(
                RawMatch(
                    start=found.start(),
                    end=found.end(),
                    value=found.group(0),
                    category=Category.IDENTIFIER,
                    subtype="aws_arn",
                    severity=Severity.SEV_3,
                    confidence=Confidence.HIGH,
                    rule_id="id.aws_arn",
                    risk_score=30,
                    remediation="Account IDs and ARNs can map infrastructure; share only if required.",
                    risk_factors=("cloud_identifier",),
                )
            )
        return matches
