from __future__ import annotations

import json
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import unquote, urlparse

import httpx


class NotificationError(RuntimeError):
    pass


class Notifier(Protocol):
    name: str

    def send(self, payload: dict[str, Any]) -> None: ...


class WebhookNotifier:
    """Generic team API: POST a sanitized JSON incident to any HTTPS endpoint."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    def send(self, payload: dict[str, Any]) -> None:
        response = httpx.post(self.url, json=payload, timeout=self.timeout)
        if response.status_code >= 400:
            raise NotificationError(f"webhook status {response.status_code}")


class PagerDutyNotifier:
    name = "pagerduty"

    def __init__(self, routing_key: str) -> None:
        self.routing_key = routing_key

    def send(self, payload: dict[str, Any]) -> None:
        body = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": payload.get("dedupe_key"),
            "payload": {
                "summary": payload.get("summary", "sentinal-trace incident"),
                "severity": payload.get("pagerduty_severity", "error"),
                "source": "sentinal-trace",
                "custom_details": payload.get("details", {}),
            },
        }
        response = httpx.post("https://events.pagerduty.com/v2/enqueue", json=body, timeout=10.0)
        if response.status_code >= 400:
            raise NotificationError(f"pagerduty status {response.status_code}")


class EmailNotifier:
    """SMTP team alert. Body is sanitized metadata only — never the pasted log."""

    name = "email"

    def __init__(self, smtp_url: str, to_addr: str, from_addr: str) -> None:
        self.smtp_url = smtp_url
        self.to_addr = to_addr
        self.from_addr = from_addr

    def send(self, payload: dict[str, Any]) -> None:
        parsed = urlparse(self.smtp_url)
        if parsed.scheme not in {"smtp", "smtps"}:
            raise NotificationError("SENTINAL_TRACE_SMTP_URL must be smtp:// or smtps://")
        host = parsed.hostname
        if not host:
            raise NotificationError("SMTP host missing")
        port = parsed.port or (465 if parsed.scheme == "smtps" else 587)
        user = unquote(parsed.username) if parsed.username else None
        password = unquote(parsed.password) if parsed.password else None

        message = EmailMessage()
        message["Subject"] = str(payload.get("summary", "sentinal-trace security incident"))
        message["From"] = self.from_addr
        message["To"] = self.to_addr
        message.set_content(
            "A credential leak was blocked before send.\n\n"
            + json.dumps(payload.get("details", {}), indent=2)
            + "\n\nRaw logs and secrets are not included."
        )

        if parsed.scheme == "smtps":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            smtp = smtplib.SMTP(host, port, timeout=15)
        try:
            smtp.ehlo()
            if parsed.scheme != "smtps":
                smtp.starttls()
                smtp.ehlo()
            if user:
                smtp.login(user, password or "")
            smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise NotificationError("smtp delivery failed") from exc
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPException:
                pass


def notifiers_from_env() -> dict[str, Notifier]:
    configured: dict[str, Notifier] = {}
    webhook = os.environ.get("SENTINAL_TRACE_WEBHOOK_URL")
    if webhook:
        configured["webhook"] = WebhookNotifier(webhook)
    pd_key = os.environ.get("SENTINAL_TRACE_PAGERDUTY_ROUTING_KEY")
    if pd_key:
        configured["pagerduty"] = PagerDutyNotifier(pd_key)
    smtp = os.environ.get("SENTINAL_TRACE_SMTP_URL")
    to_addr = os.environ.get("SENTINAL_TRACE_ALERT_EMAIL")
    if smtp and to_addr:
        configured["email"] = EmailNotifier(
            smtp,
            to_addr=to_addr,
            from_addr=os.environ.get("SENTINAL_TRACE_ALERT_FROM", "sentinal-trace@localhost"),
        )
    return configured


def sanitize_incident_payload(
    *,
    incident_id: str,
    action: str,
    category: str | None,
    severity: str | None,
    adapter: str,
) -> dict[str, Any]:
    return {
        "summary": f"sentinal-trace blocked a possible credential leak ({severity or 'n/a'})",
        "details": {
            "incident_id": incident_id,
            "action": action,
            "category": category,
            "severity": severity,
            "adapter": adapter,
            "note": "The pasted content is not included.",
        },
        "dedupe_key": f"sentinal-trace:{incident_id}:{action}",
        "pagerduty_severity": "critical" if severity in {"SEV-0", "SEV-1"} else "warning",
    }
