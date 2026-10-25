from __future__ import annotations

from sentinal_trace.detectors.base import RawMatch, to_finding
from sentinal_trace.detectors.credentials import CredentialDetector
from sentinal_trace.detectors.logs import LogLeakDetector
from sentinal_trace.detectors.network import NetworkDetector
from sentinal_trace.detectors.sensitive import SensitiveDataDetector
from sentinal_trace.models.findings import Finding
from sentinal_trace.normalization.document import NormalizedDocument

DEFAULT_DETECTORS = (
    CredentialDetector(),
    LogLeakDetector(),
    NetworkDetector(),
    SensitiveDataDetector(),
)


def collect_matches(document: NormalizedDocument) -> list[RawMatch]:
    matches: list[RawMatch] = []
    for detector in DEFAULT_DETECTORS:
        matches.extend(detector.detect(document))
    matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
    return matches


def collect_findings(document: NormalizedDocument) -> list[Finding]:
    findings: list[Finding] = []
    for index, match in enumerate(collect_matches(document), start=1):
        findings.append(to_finding(match, document, f"f-{index:04d}"))
    return findings
