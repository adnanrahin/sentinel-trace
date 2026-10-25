from __future__ import annotations

from typer.testing import CliRunner

from sentinal_trace.cli import app
from sentinal_trace.enforcement.preflight import GuardedCall, TransmissionBlocked, preflight
from sentinal_trace.pipeline import ScanSession, scan_text
from tests.conftest import SYNTHETIC_AWS

runner = CliRunner()


def test_end_to_end_block_redact_and_no_persist(session: ScanSession, monkeypatch) -> None:
    monkeypatch.setenv("SENTINAL_TRACE_HOME", str(session.settings.home))
    decision = preflight(f"send this {SYNTHETIC_AWS} to production", session=session)
    assert decision.allowed is False
    assert decision.payload is None
    dump = session.store.dump_text()
    assert SYNTHETIC_AWS not in dump
    result = scan_text("hello world", session=session)
    assert result.findings == []


def test_guarded_call_never_invokes_send(session: ScanSession) -> None:
    called = {"n": 0}

    def send(payload: str) -> str:
        called["n"] += 1
        return payload

    guarded = GuardedCall(send, session=session)
    try:
        guarded(f"AKIA {SYNTHETIC_AWS}")
        raise AssertionError("should have blocked")
    except TransmissionBlocked as exc:
        assert exc.decision.payload is None
    assert called["n"] == 0


def test_cli_scan_and_preflight(session: ScanSession, monkeypatch) -> None:
    monkeypatch.setenv("SENTINAL_TRACE_HOME", str(session.settings.home))
    scan = runner.invoke(app, ["scan", "text", "hello from sentinal-trace"])
    assert scan.exit_code == 0
    blocked = runner.invoke(app, ["preflight", "--text", f"key {SYNTHETIC_AWS}"])
    assert blocked.exit_code == 2
    assert SYNTHETIC_AWS not in blocked.stdout
    assert '"payload": null' in blocked.stdout or '"payload":null' in blocked.stdout.replace(" ", "")


def test_cli_capabilities() -> None:
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    assert "mcp" in result.stdout
    assert "does not intercept" in result.stdout.lower() or "detection-only" in result.stdout


def test_oversized_input_is_truncated(session: ScanSession) -> None:
    session.settings.max_input_bytes = 64
    result = scan_text("A" * 5000, session=session)
    assert result.limits.truncated is True
