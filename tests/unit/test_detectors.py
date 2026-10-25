from __future__ import annotations

from tests.conftest import SYNTHETIC_AWS, SYNTHETIC_GITHUB, SYNTHETIC_STRIPE

from sentinal_trace.models.enums import Category, Confidence, Severity
from sentinal_trace.pipeline import ScanSession, scan_text


def test_known_synthetic_credentials_detected(session: ScanSession) -> None:
    result = scan_text(f"token {SYNTHETIC_AWS} and {SYNTHETIC_GITHUB}", session=session)
    subtypes = {f.subtype for f in result.findings}
    assert "aws_access_key_id" in subtypes
    assert "github_pat" in subtypes
    assert all(SYNTHETIC_AWS not in f.sanitized_evidence for f in result.findings)


def test_benign_rfc1918_example_is_not_critical(session: ScanSession) -> None:
    result = scan_text("documentation example rfc1918 address 192.168.1.1", session=session)
    network = [f for f in result.findings if f.category.value == "network"]
    assert network
    assert all(f.severity == Severity.SEV_4 for f in network)
    assert all(f.confidence == Confidence.LOW for f in network)


def test_severity_and_confidence_independent(session: ScanSession) -> None:
    result = scan_text("contact alice@contoso.invalid", session=session)
    emails = [f for f in result.findings if f.subtype == "email"]
    assert emails
    assert emails[0].severity == Severity.SEV_3
    assert emails[0].confidence == Confidence.MEDIUM


def test_constructed_stripe_key_is_detected(session: ScanSession) -> None:
    result = scan_text(f"stripe {SYNTHETIC_STRIPE}", session=session)
    assert any(f.subtype == "stripe_secret_key" for f in result.findings)
    assert all(SYNTHETIC_STRIPE not in f.sanitized_evidence for f in result.findings)


def test_pasted_log_bearer_token_is_detected(session: ScanSession) -> None:
    log_line = "INFO auth failed Authorization: Bearer synthetic-demo-token-not-a-live-credential"
    result = scan_text(log_line, session=session)
    assert any(f.subtype == "bearer_token" for f in result.findings)


def test_composite_credential_plus_endpoint(session: ScanSession) -> None:
    text = f"{SYNTHETIC_AWS} talks to api.payments.internal.corp.example"
    result = scan_text(text, session=session)
    assert any(f.category is Category.COMPOSITE for f in result.findings)


def test_malformed_input_does_not_crash(session: ScanSession) -> None:
    result = scan_text("\x00\xff not-json {{{{", session=session)
    assert result.limits.errors == [] or isinstance(result.findings, list)
