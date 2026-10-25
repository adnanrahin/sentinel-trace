from __future__ import annotations

import json

from sentinal_trace.adapters.cursor_hook import handle_before_submit
from sentinal_trace.enforcement.preflight import preflight
from sentinal_trace.pipeline import ScanSession
from sentinal_trace.samples import aws_doc_example_access_key, payment_failure_log


def test_payment_log_is_blocked_and_secret_not_echoed(session: ScanSession) -> None:
    key = aws_doc_example_access_key()
    log = payment_failure_log(access_key=key)
    decision = preflight(log, session=session)
    assert decision.allowed is False
    assert decision.payload is None
    dumped = decision.model_dump_json()
    assert key not in dumped
    subtypes = {f.subtype for f in decision.findings}
    assert "aws_access_key_id" in subtypes


def test_cursor_hook_allows_payment_log_and_does_not_echo_key(session: ScanSession) -> None:
    key = aws_doc_example_access_key()
    payload = json.dumps({"prompt": payment_failure_log(access_key=key), "attachments": []})
    result = json.loads(handle_before_submit(payload, session=session))
    assert result["continue"] is True
    assert key not in json.dumps(result)
