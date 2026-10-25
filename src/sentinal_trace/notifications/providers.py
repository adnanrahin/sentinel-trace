from __future__ import annotations

import contextlib
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote, urlparse

import httpx

from sentinal_trace.config.settings import default_home

_NOTIFY_KEYS = frozenset(
    {
        "SENTINAL_TRACE_WEBHOOK_URL",
        "SENTINAL_TRACE_PAGERDUTY_ROUTING_KEY",
        "SENTINAL_TRACE_SMTP_URL",
        "SENTINAL_TRACE_ALERT_EMAIL",
        "SENTINAL_TRACE_ALERT_FROM",
    }
)


class NotificationError(RuntimeError):
    pass


_SUBTYPE_LABEL = {
    "aws_access_key_id": "AWS_ACCESS_KEY_ID",
    "github_pat": "GITHUB_PAT",
    "github_fine_grained_pat": "GITHUB_PAT",
    "stripe_secret_key": "STRIPE_SECRET_KEY",
    "slack_token": "SLACK_TOKEN",
    "jwt": "JWT",
    "connection_string": "CONNECTION_STRING",
    "pem_private_key": "PRIVATE KEY",
    "assigned_secret": "SECRET",
    "env_assigned_secret": "SECRET",
}


def names_from_findings(findings: list[Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        label = None
        for factor in getattr(finding, "risk_factors", []) or []:
            text = str(factor)
            if text.startswith("name:") and len(text) > 5:
                label = text[5:].strip().upper()
                break
        if not label:
            subtype = str(getattr(finding, "subtype", "") or "")
            label = _SUBTYPE_LABEL.get(subtype, subtype.replace("-", "_").upper() if subtype else "")
        if not label or len(label) > 80 or label in seen:
            continue
        seen.add(label)
        names.append(label)
    return names


def evidence_names(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("names")
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip() and len(str(item)) <= 80]


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
                "summary": payload.get("summary", "sentinal-trace"),
                "severity": payload.get("pagerduty_severity", "error"),
                "source": "sentinal-trace",
                "custom_details": {"names": evidence_names(payload)},
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

        names = evidence_names(payload)
        message = EmailMessage()
        message["Subject"] = names[0] if names else str(payload.get("incident_id", "sentinal-trace"))
        message["From"] = self.from_addr
        message["To"] = self.to_addr
        message.set_content("\n".join(names) + "\n" if names else "")

        context = ssl.create_default_context()
        if parsed.scheme == "smtps":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=20)
        try:
            smtp.ehlo()
            if parsed.scheme != "smtps":
                smtp.starttls(context=context)
                smtp.ehlo()
            if user:
                try:
                    smtp.login(user, password or "")
                except (smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected) as exc:
                    raise NotificationError("smtp authentication failed") from exc
            smtp.send_message(message)
        except NotificationError:
            raise
        except (OSError, smtplib.SMTPException) as exc:
            raise NotificationError("smtp delivery failed") from exc
        finally:
            with contextlib.suppress(smtplib.SMTPException, OSError):
                smtp.quit()


def _win_user_env(name: str) -> str | None:
    if sys.platform != "win32":
        return None
    try:
        import winreg
    except ImportError:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return None
    if isinstance(value, str) and value.strip():
        return value
    return None


def notify_env_path() -> Path:
    return default_home() / "notify.env"


def _parse_env_file(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return parsed
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].strip()
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key not in _NOTIFY_KEYS:
            continue
        value = value.strip().strip("'").strip('"')
        if value:
            parsed[key] = value
    return parsed


def _file_env(name: str) -> str | None:
    path = notify_env_path()
    if not path.is_file():
        return None
    return _parse_env_file(path).get(name)


def team_notify_paths() -> list[Path]:
    """Admin-placed notify file. Engineers do not set Gmail; the hook reads this on Send."""
    paths: list[Path] = []
    override = os.environ.get("SENTINAL_TRACE_TEAM_NOTIFY")
    if override:
        paths.append(Path(override))
    if sys.platform == "win32":
        root = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        paths.append(Path(root) / "sentinal-trace" / "notify.env")
    elif sys.platform == "darwin":
        paths.append(Path("/Library/Application Support/sentinal-trace/notify.env"))
    else:
        paths.append(Path("/etc/sentinal-trace/notify.env"))
    paths.append(Path.cwd() / ".sentinal-trace" / "notify.env")
    return paths


def active_team_notify_path() -> Path | None:
    for path in team_notify_paths():
        if path.is_file():
            return path
    return None


def _team_env(name: str) -> str | None:
    path = active_team_notify_path()
    if path is None:
        return None
    return _parse_env_file(path).get(name)


def env_get(name: str) -> str | None:
    """Personal Windows env, user notify.env, team notify.env, then this process."""
    win_value = _win_user_env(name)
    if win_value:
        return win_value
    file_value = _file_env(name)
    if file_value:
        return file_value
    team_value = _team_env(name)
    if team_value:
        return team_value
    value = os.environ.get(name)
    if value and value.strip():
        return value
    return None


def notify_identity() -> dict[str, str | None]:
    smtp = env_get("SENTINAL_TRACE_SMTP_URL")
    login = None
    if smtp:
        parsed = urlparse(smtp)
        login = unquote(parsed.username) if parsed.username else None
    return {
        "smtp_login": login,
        "alert_email": env_get("SENTINAL_TRACE_ALERT_EMAIL"),
        "alert_from": env_get("SENTINAL_TRACE_ALERT_FROM"),
    }


def save_notify_env() -> list[str]:
    """Persist Git Bash/process notify vars so the Cursor hook can send without export."""
    lines = ["# Written by sentinal-trace. Do not commit.", ""]
    saved: list[str] = []
    for key in sorted(_NOTIFY_KEYS):
        value = (os.environ.get(key) or "").strip().strip("'").strip('"')
        if not value:
            continue
        if "\n" in value or "\r" in value:
            continue
        lines.append(f"{key}={value}")
        saved.append(key)
    if not saved:
        return []
    path = notify_env_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return saved


def notify_env_visibility() -> dict[str, bool]:
    return {
        "SENTINAL_TRACE_SMTP_URL": bool(env_get("SENTINAL_TRACE_SMTP_URL")),
        "SENTINAL_TRACE_ALERT_EMAIL": bool(env_get("SENTINAL_TRACE_ALERT_EMAIL")),
        "SENTINAL_TRACE_ALERT_FROM": bool(env_get("SENTINAL_TRACE_ALERT_FROM")),
        "SENTINAL_TRACE_WEBHOOK_URL": bool(env_get("SENTINAL_TRACE_WEBHOOK_URL")),
        "SENTINAL_TRACE_PAGERDUTY_ROUTING_KEY": bool(env_get("SENTINAL_TRACE_PAGERDUTY_ROUTING_KEY")),
    }


def notifiers_from_env() -> dict[str, Notifier]:
    configured: dict[str, Notifier] = {}
    webhook = env_get("SENTINAL_TRACE_WEBHOOK_URL")
    if webhook:
        configured["webhook"] = WebhookNotifier(webhook)
    pd_key = env_get("SENTINAL_TRACE_PAGERDUTY_ROUTING_KEY")
    if pd_key:
        configured["pagerduty"] = PagerDutyNotifier(pd_key)
    smtp = env_get("SENTINAL_TRACE_SMTP_URL")
    to_addr = env_get("SENTINAL_TRACE_ALERT_EMAIL")
    if smtp and to_addr:
        configured["email"] = EmailNotifier(
            smtp,
            to_addr=to_addr,
            from_addr=env_get("SENTINAL_TRACE_ALERT_FROM") or "sentinal-trace@localhost",
        )
    return configured


def sanitize_incident_payload(
    *,
    incident_id: str,
    action: str,
    category: str | None,
    severity: str | None,
    adapter: str,
    names: list[str] | None = None,
) -> dict[str, Any]:
    labels = evidence_names({"names": list(names or [])})
    summary = "\n".join(labels) if labels else incident_id
    return {
        "summary": summary,
        "names": labels,
        "incident_id": incident_id,
        "dedupe_key": f"sentinal-trace:{incident_id}:{action}",
        "pagerduty_severity": "critical" if severity in {"SEV-0", "SEV-1"} else "warning",
    }
