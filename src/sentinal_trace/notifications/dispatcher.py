from __future__ import annotations

import json
import logging

from sentinal_trace.audit.store import AuditStore
from sentinal_trace.notifications.providers import NotificationError, Notifier, sanitize_incident_payload
from sentinal_trace.security.sanitize import scrub_for_log

log = logging.getLogger(__name__)


def enqueue_incident(
    store: AuditStore,
    *,
    incident_id: str,
    action: str,
    category: str | None,
    severity: str | None,
    adapter: str,
    providers: list[str],
    names: list[str] | None = None,
) -> None:
    payload = sanitize_incident_payload(
        incident_id=incident_id,
        action=action,
        category=category,
        severity=severity,
        adapter=adapter,
        names=names,
    )
    body = json.dumps(payload)
    for provider in providers:
        store.enqueue_notification(
            incident_id=incident_id,
            provider=provider,
            payload=body,
            dedupe_key=f"{payload['dedupe_key']}:{provider}",
        )


def drain_outbox(store: AuditStore, notifiers: dict[str, Notifier]) -> None:
    for item in store.pending_notifications():
        notifier = notifiers.get(str(item["provider"]))
        if notifier is None:
            store.mark_notification(str(item["id"]), "failed", "unknown provider")
            continue
        try:
            notifier.send(json.loads(item["payload"]))
            store.mark_notification(str(item["id"]), "sent")
        except (NotificationError, OSError, ValueError) as exc:
            log.warning("notification delivery failed: %s", scrub_for_log(str(exc)))
            store.mark_notification(str(item["id"]), "pending", str(exc)[:200])
