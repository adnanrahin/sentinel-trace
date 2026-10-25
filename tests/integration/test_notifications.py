from __future__ import annotations

import json

from tests.conftest import SYNTHETIC_AWS

from sentinal_trace.audit.store import AuditStore
from sentinal_trace.config.settings import AppSettings
from sentinal_trace.enforcement.preflight import preflight
from sentinal_trace.notifications.dispatcher import drain_outbox, enqueue_incident
from sentinal_trace.pipeline import ScanSession


class RecordingNotifier:
    name = "webhook"

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, payload: dict) -> None:
        self.sent.append(payload)


class BoomNotifier:
    name = "pagerduty"

    def send(self, payload: dict) -> None:
        raise OSError("network down")


def test_outbox_sanitized_and_deduped(session: ScanSession) -> None:
    incident = session.store.record_incident(
        adapter="cli",
        source="<input>",
        category="credential",
        severity="SEV-0",
        confidence="confirmed",
        action="block",
        rule_version="1",
        fingerprint="abc",
    )
    enqueue_incident(
        session.store,
        incident_id=incident,
        action="block",
        category="credential",
        severity="SEV-0",
        adapter="cli",
        providers=["webhook"],
    )
    enqueue_incident(
        session.store,
        incident_id=incident,
        action="block",
        category="credential",
        severity="SEV-0",
        adapter="cli",
        providers=["webhook"],
    )
    recorder = RecordingNotifier()
    drain_outbox(session.store, {"webhook": recorder})
    assert len(recorder.sent) == 1
    assert SYNTHETIC_AWS not in str(recorder.sent[0])
    assert "prompt" not in str(recorder.sent[0])


def test_notification_failure_does_not_raise(session: ScanSession) -> None:
    incident = session.store.record_incident(
        adapter="cli",
        source=None,
        category="credential",
        severity="SEV-0",
        confidence="high",
        action="block",
        rule_version="1",
        fingerprint=None,
    )
    enqueue_incident(
        session.store,
        incident_id=incident,
        action="block",
        category="credential",
        severity="SEV-0",
        adapter="cli",
        providers=["pagerduty"],
    )
    drain_outbox(session.store, {"pagerduty": BoomNotifier()})
    pending = session.store.pending_notifications()
    assert pending


def test_block_sends_sanitized_team_alert(tmp_path) -> None:
    recorder = RecordingNotifier()
    session = ScanSession(AppSettings(home=tmp_path / "home"), notifiers={"webhook": recorder})
    decision = preflight(f"paste {SYNTHETIC_AWS}", session=session)
    assert decision.allowed is False
    assert recorder.sent
    blob = json.dumps(recorder.sent)
    assert SYNTHETIC_AWS not in blob
    assert "prompt" not in blob
    assert "AWS_ACCESS_KEY_ID" in recorder.sent[0]["names"]
    assert recorder.sent[0]["user"]
    assert recorder.sent[0]["when"]
    assert recorder.sent[0]["host"]
    assert "leak" not in blob.lower()
    assert "security" not in blob.lower()


def test_audit_store_schema(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    store.close()
    assert (tmp_path / "audit.db").exists()
