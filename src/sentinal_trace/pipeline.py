from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, overload

from sentinal_trace.audit.store import AuditStore
from sentinal_trace.config.settings import AppSettings
from sentinal_trace.context.engine import apply_context
from sentinal_trace.detectors.base import RawMatch, to_finding
from sentinal_trace.detectors.engine import collect_matches
from sentinal_trace.models.enums import PolicyAction
from sentinal_trace.models.findings import Finding, ScanResult
from sentinal_trace.normalization.document import NormalizedDocument, normalize_file, normalize_text
from sentinal_trace.notifications.dispatcher import drain_outbox, enqueue_incident
from sentinal_trace.notifications.providers import Notifier, notifiers_from_env
from sentinal_trace.policy.engine import PolicyConfig, evaluate_policy, load_policy
from sentinal_trace.security.hmac_key import load_or_create_hmac_key
from sentinal_trace.security.paths import PathSecurityError, iter_files, resolve_within
from sentinal_trace.security.sanitize import fingerprint_value


class ScanSession:
    def __init__(
        self,
        settings: AppSettings,
        policy: PolicyConfig | None = None,
        notifiers: dict[str, Notifier] | None = None,
    ) -> None:
        self.settings = settings
        settings.home.mkdir(parents=True, exist_ok=True)
        self.policy = policy or load_policy(settings.policy_path if settings.policy_path.exists() else None)
        self.store = AuditStore(settings.db_path)
        self._hmac_key = load_or_create_hmac_key(settings.hmac_key_path)
        self._notifiers = notifiers

    def fingerprint(self, value: str) -> str:
        return fingerprint_value(value, self._hmac_key)

    def _active_notifiers(self) -> dict[str, Notifier]:
        if self._notifiers is not None:
            return self._notifiers
        return notifiers_from_env()

    def record(self, result: ScanResult, action: PolicyAction) -> str | None:
        if not result.findings and action in {PolicyAction.ALLOW}:
            return None
        top = min(result.findings, key=lambda f: (f.severity.rank, f.confidence.rank), default=None)
        fingerprint = top.fingerprint if top else None
        try:
            incident_id = self.store.record_incident(
                adapter=result.adapter,
                source=result.source,
                category=top.category.value if top else None,
                severity=top.severity.value if top else None,
                confidence=top.confidence.value if top else None,
                action=action.value,
                rule_version=result.policy_version,
                fingerprint=fingerprint,
            )
        except Exception:
            return None
        if action in self.policy.notify_on and incident_id:
            self._alert(incident_id, action, result.findings, top)
        return incident_id

    def _alert(
        self,
        incident_id: str,
        action: PolicyAction,
        findings: list[Finding],
        top: Finding | None,
    ) -> None:
        notifiers = self._active_notifiers()
        if not notifiers:
            return
        from sentinal_trace.notifications.providers import names_from_findings

        try:
            enqueue_incident(
                self.store,
                incident_id=incident_id,
                action=action.value,
                category=top.category.value if top else None,
                severity=top.severity.value if top else None,
                adapter="sentinal-trace",
                providers=list(notifiers),
                names=names_from_findings(findings),
            )
            drain_outbox(self.store, notifiers)
        except Exception:
            return


def _findings_from(document: NormalizedDocument, matches: list[RawMatch], session: ScanSession) -> list[Finding]:
    findings: list[Finding] = []
    for index, match in enumerate(matches, start=1):
        finding = to_finding(match, document, f"f-{index:04d}")
        if match.value:
            finding.fingerprint = session.fingerprint(match.value)
        findings.append(finding)
    return findings


def _run_document(
    document: NormalizedDocument,
    *,
    adapter: str,
    source: str,
    session: ScanSession,
) -> tuple[ScanResult, list[RawMatch], NormalizedDocument]:
    try:
        matches = apply_context(document, list(collect_matches(document)))
    except Exception as exc:
        result = ScanResult(
            adapter=adapter,
            source=source,
            limits=document.limits,
        )
        result.limits.errors.append(f"scan_error:{type(exc).__name__}")
        evaluate_policy(result, session.policy)
        return result, [], document
    findings = _findings_from(document, matches, session)
    result = ScanResult(
        findings=findings,
        adapter=adapter,
        source=source,
        limits=document.limits,
        rule_set_version="1",
    )
    evaluate_policy(result, session.policy)
    return result, matches, document


@overload
def scan_text(
    text: str,
    *,
    source: str = "<stdin>",
    adapter: str = "cli",
    session: ScanSession | None = None,
    raw: Literal[False] = False,
) -> ScanResult: ...


@overload
def scan_text(
    text: str,
    *,
    source: str = "<stdin>",
    adapter: str = "cli",
    session: ScanSession | None = None,
    raw: Literal[True],
) -> tuple[ScanResult, list[RawMatch], NormalizedDocument]: ...


def scan_text(
    text: str,
    *,
    source: str = "<stdin>",
    adapter: str = "cli",
    session: ScanSession | None = None,
    raw: bool = False,
) -> ScanResult | tuple[ScanResult, list[RawMatch], NormalizedDocument]:
    session = session or ScanSession(AppSettings())
    document = normalize_text(text, path=None if source.startswith("<") else source, settings=session.settings)
    result, matches, document = _run_document(document, adapter=adapter, source=source, session=session)
    if raw:
        return result, matches, document
    return result


def scan_path(
    path: str | Path,
    *,
    root: str | Path | None = None,
    adapter: str = "cli",
    session: ScanSession | None = None,
) -> ScanResult:
    session = session or ScanSession(AppSettings())
    root_path = Path(root) if root else Path.cwd()
    target = resolve_within(path, root_path)
    if target.is_dir():
        combined = ScanResult(adapter=adapter, source=str(target))
        for file_path in iter_files(target, follow_symlinks=session.settings.follow_symlinks):
            try:
                resolve_within(file_path, root_path)
            except PathSecurityError:
                combined.limits.errors.append("skipped_escaped_path")
                continue
            document = normalize_file(file_path, settings=session.settings)
            part, _, _ = _run_document(document, adapter=adapter, source=str(file_path), session=session)
            combined.findings.extend(part.findings)
            combined.limits.errors.extend(part.limits.errors)
            combined.limits.bytes_scanned += part.limits.bytes_scanned
            combined.limits.truncated = combined.limits.truncated or part.limits.truncated
        evaluate_policy(combined, session.policy)
        return combined
    document = normalize_file(target, settings=session.settings)
    result, _, _ = _run_document(document, adapter=adapter, source=str(target), session=session)
    return result


def result_to_dict(result: ScanResult) -> dict[str, Any]:
    return result.model_dump(mode="json")
