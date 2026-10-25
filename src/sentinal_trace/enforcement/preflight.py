from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from sentinal_trace.config.settings import AppSettings
from sentinal_trace.models.decisions import PreflightDecision
from sentinal_trace.models.enums import PolicyAction
from sentinal_trace.pipeline import ScanSession, scan_text

T = TypeVar("T")


class TransmissionBlocked(RuntimeError):
    def __init__(self, decision: PreflightDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def preflight(
    content: str,
    *,
    source: str = "<input>",
    adapter: str = "preflight",
    session: ScanSession | None = None,
    approved: bool = False,
) -> PreflightDecision:
    """Scan content and return an explicit send decision.

    Callers MUST check ``allowed`` (or catch ``TransmissionBlocked``). A blocked
    decision never includes a payload.
    """
    session = session or ScanSession(AppSettings())
    result, matches, document = scan_text(content, source=source, adapter=adapter, session=session, raw=True)
    action = result.policy_action or PolicyAction.ALLOW
    findings = result.findings
    policy_version = result.policy_version or session.policy.version

    if action is PolicyAction.REQUIRE_APPROVAL and not approved:
        action = PolicyAction.BLOCK

    if action is PolicyAction.BLOCK:
        incident_id = session.record(result, action)
        return PreflightDecision(
            allowed=False,
            verdict=PolicyAction.BLOCK,
            content_changed=False,
            payload=None,
            findings=findings,
            reason="Policy blocked transmission of sensitive content.",
            policy_version=policy_version,
            adapter=adapter,
            incident_id=incident_id,
        )

    if action is PolicyAction.REDACT:
        from sentinal_trace.enforcement.redact import redact_matches

        redacted = redact_matches(document.text, matches)
        incident_id = session.record(result, action)
        return PreflightDecision(
            allowed=True,
            verdict=PolicyAction.REDACT,
            content_changed=redacted != document.text,
            payload=redacted,
            findings=findings,
            reason="Sensitive values were redacted before send.",
            policy_version=policy_version,
            adapter=adapter,
            incident_id=incident_id,
        )

    incident_id = session.record(result, action)
    reason = {
        PolicyAction.WARN: "Findings present; transmission allowed with warning.",
        PolicyAction.AUDIT: "Findings recorded; transmission allowed.",
        PolicyAction.ALLOW: "No blocking policy matched.",
    }.get(action, "Transmission allowed.")
    return PreflightDecision(
        allowed=True,
        verdict=action,
        content_changed=False,
        payload=document.text,
        findings=findings,
        reason=reason,
        policy_version=policy_version,
        adapter=adapter,
        incident_id=incident_id,
    )


class GuardedCall:
    """Wrap an LLM (or any send) function so blocked content is never submitted."""

    def __init__(self, send: Callable[[str], T], *, session: ScanSession | None = None) -> None:
        self._send = send
        self._session = session

    def __call__(self, content: str) -> T:
        decision = preflight(content, adapter="python_guard", session=self._session)
        if not decision.allowed or decision.payload is None:
            raise TransmissionBlocked(decision)
        return self._send(decision.payload)
