"""Sentinal Trace — local-first AI security exposure prevention."""

from sentinal_trace.__version__ import __version__
from sentinal_trace.enforcement.preflight import GuardedCall, preflight
from sentinal_trace.models.enums import AdapterCapability, Confidence, PolicyAction, Severity
from sentinal_trace.models.findings import Finding, ScanResult
from sentinal_trace.pipeline import scan_path, scan_text

__all__ = [
    "AdapterCapability",
    "Confidence",
    "Finding",
    "GuardedCall",
    "PolicyAction",
    "ScanResult",
    "Severity",
    "__version__",
    "preflight",
    "scan_path",
    "scan_text",
]
