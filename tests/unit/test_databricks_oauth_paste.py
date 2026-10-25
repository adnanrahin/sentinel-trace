from __future__ import annotations

from sentinal_trace.enforcement.preflight import preflight
from sentinal_trace.models.enums import PolicyAction
from sentinal_trace.notifications.providers import names_from_findings
from sentinal_trace.pipeline import ScanSession
from sentinal_trace.samples import databricks_oauth_debug_log


def test_databricks_client_secret_env_is_blocked(session: ScanSession) -> None:
    secret = "dose-not-a-real-databricks-oauth-secret"
    decision = preflight(databricks_oauth_debug_log(client_secret=secret), session=session)
    assert decision.allowed is False
    assert decision.verdict is PolicyAction.BLOCK
    assert "env_assigned_secret" in {f.subtype for f in decision.findings}
    assert secret not in decision.model_dump_json()
    assert names_from_findings(decision.findings) == ["DATABRICKS_CLIENT_SECRET"]


def test_secret_env_name_is_enough_to_name_the_credential(session: ScanSession) -> None:
    text = "In `DATABRICKS_CLIENT_SECRET=...`, SECRET is preceded by `_`."
    decision = preflight(text, session=session)
    assert "DATABRICKS_CLIENT_SECRET" in names_from_findings(decision.findings)
    assert "..." not in names_from_findings(decision.findings)
